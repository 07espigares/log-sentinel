import io
import json
from datetime import datetime, timedelta
from pathlib import Path

from logsentinel.__main__ import Mode, main, run_follow
from logsentinel.dashboard import build_dashboard, dashboard_from
from logsentinel.detectors import Config, Finding, Severity, analyze
from logsentinel.parser import parse_lines

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
AUTH = SAMPLES / "auth.log"
ACCESS = SAMPLES / "access.log"


def test_web_text_and_json(capsys):
    assert main([str(ACCESS), "--web"]) == 1
    out = capsys.readouterr().out
    assert "Inyección SQL" in out and "(web)" in out

    assert main([str(ACCESS), "--web", "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["kind"] == "web"
    assert {f["rule"] for f in data["findings"]} >= {"sqli", "rce", "path_traversal"}


def test_web_dashboard(tmp_path, capsys):
    panel = tmp_path / "panel.html"
    main([str(ACCESS), "--web", "--dashboard", str(panel)])
    html = panel.read_text()
    assert html.lower().startswith("<!doctype html>")
    assert "Inyección SQL" in html


def test_dashboard_is_self_contained():
    analysis = analyze(list(parse_lines(AUTH.read_text().splitlines(), 2026)))
    html = dashboard_from(analysis, "auth.log", "ssh")
    # Nada de fuera: ni scripts, ni hojas de estilo, ni imágenes remotas.
    assert 'src="http' not in html and 'href="http' not in html
    assert "<script" not in html.lower()
    assert "default-src 'none'" in html  # y la CSP prohíbe cargarlos aunque se colaran
    assert "T1078 Valid Accounts" in html


def test_dashboard_escapes_html():
    evil = Finding(
        Severity.HIGH,
        "x",
        "<script>alert(1)</script>",
        datetime(2026, 1, 1),
        datetime(2026, 1, 1),
        1,
        ip="<b>",
        details="a & b",
    )
    html = build_dashboard([evil], [("<b>", 1)], [("X", 1)], "s")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html and "&amp;" in html


def test_escape_sequences_from_the_log_are_not_printed(tmp_path, capsys):
    # Un atacante puede elegir el nombre de usuario que prueba por SSH.
    evil_user = "\x1b[2J\x1b]0;hola\x07"
    lines = [
        f"Sep 25 10:00:{i:02d} srv sshd[1]: Invalid user {evil_user}{i} from 203.0.113.3 port 22" for i in range(6)
    ]
    log = tmp_path / "auth.log"
    log.write_text("\n".join(lines) + "\n")
    main([str(log), "--year", "2026"])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "\\x1b[2J" in out


def test_markdown_report_escapes_the_log(tmp_path, capsys):
    lines = [
        f'203.0.113.5 - - [25/Sep/2026:10:00:0{i} +0200] "GET /q=<script>![x](http://evil.test/p.png)|{i} HTTP/1.1" '
        f'200 1 "-" "x"'
        for i in range(2)
    ]
    log = tmp_path / "access.log"
    log.write_text("\n".join(lines) + "\n")
    main([str(log), "--web", "--format", "md"])
    out = capsys.readouterr().out
    assert "<script>" not in out and "![x](" not in out
    assert "\\<script\\>" in out and "\\!\\[x\\]" in out


def test_clean_log_exits_zero(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("Sep 25 10:00:00 srv sshd[1]: Accepted publickey for alice from 198.51.100.1 port 1 ssh2\n")
    assert main([str(log), "--year", "2026"]) == 0
    assert "Sin hallazgos" in capsys.readouterr().out
    assert main([str(log), "--year", "2026", "--format", "md"]) == 0
    assert "# Informe de log-sentinel" in capsys.readouterr().out


def test_cannot_write_dashboard(tmp_path, capsys):
    assert main([str(AUTH), "--year", "2026", "--dashboard", str(tmp_path / "no" / "existe.html")]) == 2
    assert "no se pudo escribir" in capsys.readouterr().err


def test_notify_needs_credentials(monkeypatch, capsys):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    assert main([str(AUTH), "--follow", "--notify", "telegram"]) == 2
    assert "TELEGRAM" in capsys.readouterr().err


def test_notify_without_follow_warns(capsys):
    main([str(AUTH), "--year", "2026", "--notify", "telegram"])
    assert "solo se usa junto con --follow" in capsys.readouterr().err


# Modo en vivo


class RecordingNotifier:
    name = "test"

    def __init__(self):
        self.sent = []

    def send(self, finding, host=""):
        self.sent.append(finding)


def syslog_burst(ip, n, user="root"):
    t0 = datetime(2026, 9, 25, 12, 0, 0)
    times = [t0 + timedelta(seconds=i) for i in range(n)]
    return [
        f"{t:%b} {t.day:>2} {t:%H:%M:%S} srv sshd[1]: Failed password for {user} from {ip} port 22 ssh2" for t in times
    ]


def follow(log, notifier, min_sev=Severity.HIGH):
    out = io.StringIO()
    calls = {"n": 0}

    def stop():  # para después de unas pocas vueltas
        calls["n"] += 1
        return calls["n"] > 3

    code = run_follow(
        log,
        Mode(web=False),
        Config(brute_force_threshold=10),
        [notifier],
        min_sev,
        "srv",
        out,
        from_start=True,
        stop=stop,
        sleep=lambda _: None,
    )
    return code, out.getvalue()


def test_follow_prints_but_does_not_send_below_min_severity(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(syslog_burst("203.0.113.9", 12)) + "\n")
    notifier = RecordingNotifier()
    code, out = follow(log, notifier)
    assert code == 0 and "vigilando" in out
    assert "Fuerza bruta" in out  # es MEDIA: se ve en pantalla...
    assert notifier.sent == []  # ...pero no se manda


def test_follow_sends_high_severity(tmp_path):
    log = tmp_path / "auth.log"
    # 6 IPs distintas contra 'admin': ataque distribuido, prioridad ALTA
    lines = [line for i in range(1, 7) for line in syslog_burst(f"192.0.2.{i}", 2, "admin")]
    log.write_text("\n".join(lines) + "\n")
    notifier = RecordingNotifier()
    follow(log, notifier)
    assert [f.rule for f in notifier.sent] == ["distributed_attack"]


def test_follow_keeps_going_if_a_notification_fails(tmp_path):
    from logsentinel.notifier import NotifyError

    class Broken:
        name = "roto"

        def send(self, finding, host=""):
            raise NotifyError("sin red")

    log = tmp_path / "auth.log"
    lines = [line for i in range(1, 7) for line in syslog_burst(f"192.0.2.{i}", 2, "admin")]
    log.write_text("\n".join(lines) + "\n")
    code, out = follow(log, Broken())
    assert code == 0
    assert "no se pudo avisar por roto" in out


def test_follow_rejects_stdin_gz_and_directories(tmp_path):
    for path in ["-", "x.log.gz", tmp_path]:
        assert run_follow(path, Mode(False), Config(), [], Severity.HIGH, "", io.StringIO()) == 2


def test_invalid_window_is_a_usage_error(tmp_path, capsys):
    import pytest

    log = tmp_path / "auth.log"
    log.write_text("Sep 25 10:00:01 srv sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2\n")
    for bad in (["--window", "-1"], ["--window", "0"], ["--threshold", "0"]):
        with pytest.raises(SystemExit) as exc:
            main([str(log), *bad])
        assert exc.value.code == 2


def test_warns_when_no_line_is_understood(tmp_path, capsys):
    # Sin este aviso, un log equivocado (p. ej. uno web sin --web) sale como «Sin hallazgos».
    log = tmp_path / "access.log"
    log.write_text('203.0.113.1 - - [25/Sep/2026:10:00:00 +0200] "GET / HTTP/1.1" 200 5 "-" "x"\n' * 3)
    main([str(log)])
    err = capsys.readouterr().err
    assert "ninguna de las 3 líneas" in err and "--web" in err


def test_since_and_until_limit_the_analysis(tmp_path, capsys):
    log = tmp_path / "auth.log"
    lines = [
        f"Sep 25 10:00:{i:02d} srv sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2" for i in range(10)
    ]
    lines += [
        f"Sep 27 10:00:{i:02d} srv sshd[1]: Failed password for root from 203.0.113.6 port 1 ssh2" for i in range(10)
    ]
    log.write_text("\n".join(lines) + "\n")
    main([str(log), "--year", "2026", "--format", "json", "--since", "2026-09-26"])
    report = json.loads(capsys.readouterr().out)
    assert {f["ip"] for f in report["findings"]} == {"203.0.113.6"}
    main([str(log), "--year", "2026", "--format", "json", "--until", "2026-09-25 23:59"])
    report = json.loads(capsys.readouterr().out)
    assert {f["ip"] for f in report["findings"]} == {"203.0.113.5"}


def test_bad_since_date_is_a_usage_error(capsys):
    import pytest

    with pytest.raises(SystemExit) as exc:
        main(["x.log", "--since", "ayer"])
    assert exc.value.code == 2


def test_until_a_date_includes_that_whole_day():
    from logsentinel.__main__ import when_end

    assert when_end("2026-09-25") == datetime(2026, 9, 25, 23, 59, 59, 999999)
    assert when_end("2026-09-25 10:30") == datetime(2026, 9, 25, 10, 30)


def test_since_with_timezone_does_not_crash(tmp_path, capsys):
    # Igual que el parser con las fechas ISO, se usa la hora tal como está escrita.
    log = tmp_path / "auth.log"
    log.write_text("Sep 25 10:00:01 srv sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2\n")
    assert main([str(log), "--year", "2026", "--since", "2026-09-25T00:00:00+02:00"]) == 0

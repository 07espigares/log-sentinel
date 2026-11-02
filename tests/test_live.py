import os
from datetime import datetime, timedelta

from logsentinel import Config, analyze
from logsentinel.follow import Tailer
from logsentinel.live import LiveEngine
from logsentinel.parser import parse_lines

T0 = datetime(2026, 9, 25, 12, 0, 0)


# Tailer


def test_tailer_reads_only_new_lines(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("vieja 1\nvieja 2\n")
    tailer = Tailer(log)  # empieza por el final: lo que ya estaba no cuenta
    assert tailer.read_new() == []
    with open(log, "a") as fh:
        fh.write("nueva 1\nnueva 2\n")
    assert tailer.read_new() == ["nueva 1", "nueva 2"]
    tailer.close()


def test_tailer_from_start_reads_everything(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("uno\ndos\n")
    assert Tailer(log, from_start=True).read_new() == ["uno", "dos"]


def test_tailer_waits_for_complete_lines(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("")
    tailer = Tailer(log, from_start=True)
    with open(log, "a") as fh:
        fh.write("media ")
    assert tailer.read_new() == []
    with open(log, "a") as fh:
        fh.write("línea\n")
    assert tailer.read_new() == ["media línea"]


def test_tailer_utf8_character_split_between_reads(tmp_path):
    log = tmp_path / "a.log"
    log.write_bytes(b"")
    tailer = Tailer(log, from_start=True)
    data = "usuario inválido\n".encode()
    cut = data.index("á".encode()) + 1  # corta la "á" por la mitad
    with open(log, "ab") as fh:
        fh.write(data[:cut])
    assert tailer.read_new() == []
    with open(log, "ab") as fh:
        fh.write(data[cut:])
    assert tailer.read_new() == ["usuario inválido"]


def test_tailer_handles_rotation(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("antes\n")
    tailer = Tailer(log, from_start=True)
    assert tailer.read_new() == ["antes"]
    with open(log, "a") as fh:
        fh.write("justo antes de rotar\n")  # escrito en el viejo pero aún no leído
    os.replace(log, tmp_path / "a.log.1")
    log.write_text("después\n")
    assert tailer.read_new() == ["justo antes de rotar", "después"]


def test_tailer_handles_truncation(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("largo largo largo\n")
    tailer = Tailer(log, from_start=True)
    tailer.read_new()
    log.write_text("x\n")
    assert tailer.read_new() == ["x"]


def test_tailer_file_that_appears_later(tmp_path):
    log = tmp_path / "todavia-no-existe.log"
    tailer = Tailer(log)
    assert tailer.read_new() == []
    log.write_text("primera\n")
    assert tailer.read_new() == ["primera"]  # todo lo del fichero nuevo es nuevo


# LiveEngine


def failed(t: datetime, ip: str, user: str = "root") -> str:
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S} srv sshd[1]: Failed password for {user} from {ip} port 22 ssh2"


def burst(ip: str, n: int, start: int = 0, user: str = "root") -> list[str]:
    return [failed(T0 + timedelta(seconds=start + i), ip, user) for i in range(n)]


def make_engine(seen, now=T0 + timedelta(hours=1), **kw):
    def parse(lines):
        return parse_lines(lines, now=now)

    return LiveEngine(parse, analyze, Config(brute_force_threshold=5), seen.append, **kw)


def test_live_emits_when_the_threshold_is_crossed():
    seen = []
    engine = make_engine(seen)
    engine.feed(burst("203.0.113.9", 4))
    assert seen == []
    engine.feed(burst("203.0.113.9", 1, start=4))
    assert [f.rule for f in seen] == ["brute_force"]


def test_live_does_not_repeat_the_same_finding():
    seen = []
    engine = make_engine(seen)
    engine.feed(burst("203.0.113.50", 6))
    engine.feed(burst("203.0.113.50", 1, start=6))
    assert len(seen) == 1


def test_live_same_attack_against_another_user_is_not_a_new_alert():
    seen = []
    engine = make_engine(seen)
    engine.feed(burst("203.0.113.1", 6, user="root"))
    engine.feed(burst("203.0.113.1", 2, start=60, user="admin"))
    assert [(f.rule, f.ip) for f in seen] == [("brute_force", "203.0.113.1")]


def test_live_reports_a_new_ip_separately():
    seen = []
    engine = make_engine(seen)
    engine.feed(burst("203.0.113.1", 6))
    engine.feed(burst("203.0.113.2", 6))
    assert {f.ip for f in seen} == {"203.0.113.1", "203.0.113.2"}


def test_live_prunes_old_events():
    engine = make_engine([], horizon=timedelta(seconds=30))
    engine.feed(burst("203.0.113.1", 1))
    engine.feed(burst("203.0.113.2", 1, start=1000))
    assert all(e.ip == "203.0.113.2" for e in engine.events)


def test_live_keeps_working_after_new_year():
    # El año se deduce del reloj en cada lectura, así que el 1 de enero sigue detectando.
    seen = []
    clock = {"now": datetime(2026, 12, 31, 23, 59, 59)}
    engine = LiveEngine(
        lambda lines: parse_lines(lines, now=clock["now"]), analyze, Config(brute_force_threshold=5), seen.append
    )
    engine.feed([failed(datetime(2026, 12, 31, 23, 59, s), "203.0.113.1") for s in range(50, 52)])
    clock["now"] = datetime(2027, 1, 1, 0, 1)
    engine.feed([failed(datetime(2027, 1, 1, 0, 0, s), "203.0.113.9") for s in range(10)])
    assert [(f.rule, f.ip) for f in seen] == [("brute_force", "203.0.113.9")]


def sqli(ts: datetime) -> str:
    return f'192.0.2.66 - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "GET /?id=1+union+select+1 HTTP/1.1" 200 5 "-" "x"'


def test_attack_that_comes_back_after_a_quiet_period_is_alerted_again():
    from logsentinel.webserver import analyze_web, parse_web_lines

    alerts = []
    engine = LiveEngine(parse_web_lines, analyze_web, Config(), alerts.append)
    engine.feed([sqli(T0)])
    engine.feed([sqli(T0 + timedelta(hours=3))])  # nada entre medias: el primer ataque ya caducó
    assert len(alerts) == 2

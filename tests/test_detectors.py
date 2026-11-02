import json
from datetime import datetime, timedelta
from pathlib import Path

from logsentinel import AuthEvent, Config, EventKind, Severity, analyze
from logsentinel.__main__ import main

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "auth.log"
T0 = datetime(2026, 9, 25, 12, 0, 0)


def fail(seconds: float, user: str, ip: str, invalid: bool = False) -> AuthEvent:
    return AuthEvent(T0 + timedelta(seconds=seconds), "srv", EventKind.FAILED, user, ip, "password", invalid)


def ok(seconds: float, user: str, ip: str) -> AuthEvent:
    return AuthEvent(T0 + timedelta(seconds=seconds), "srv", EventKind.ACCEPTED, user, ip, "password")


def rules(events, cfg=None):
    return sorted(f.rule for f in analyze(events, cfg).findings)


def test_brute_force_needs_threshold_inside_window():
    fast = [fail(i * 10, "root", "203.0.113.1") for i in range(10)]  # 10 fallos en 90 s
    assert rules(fast) == ["brute_force"]
    slow = [fail(i * 600, "root", "203.0.113.1") for i in range(10)]  # 10 fallos en 90 min
    assert rules(slow) == []


def test_brute_force_threshold_is_configurable():
    events = [fail(i, "root", "203.0.113.1") for i in range(4)]
    assert rules(events, Config(brute_force_threshold=4)) == ["brute_force"]


def test_single_typo_is_not_an_alert():
    assert rules([fail(0, "bob", "198.51.100.1"), ok(5, "bob", "198.51.100.1")]) == []


def test_success_after_failures_is_critical():
    events = [fail(i, "backup", "203.0.113.9") for i in range(5)] + [ok(10, "backup", "203.0.113.9")]
    finding = analyze(events).findings[0]
    assert finding.rule == "success_after_failures"
    assert finding.severity is Severity.CRITICAL
    assert finding.user == "backup" and finding.count == 5


def test_password_spraying_only_counts_existing_accounts():
    real = [fail(i * 30, user, "203.0.113.7") for i, user in enumerate(["a", "b", "c", "d", "e"])]
    assert rules(real) == ["password_spraying"]
    ghosts = [fail(i * 30, f"u{i}", "203.0.113.8", invalid=True) for i in range(5)]
    assert rules(ghosts) == ["user_enumeration"]


def test_many_attempts_per_user_is_brute_force_not_spraying():
    events = [fail(i, user, "203.0.113.7") for i in range(0, 50, 2) for user in ["a", "b", "c", "d", "e"]]
    assert "password_spraying" not in rules(events)
    assert "brute_force" in rules(events)


def test_distributed_attack_against_one_account():
    events = [fail(i * 120, "admin", f"192.0.2.{i}") for i in range(1, 7)]
    finding = analyze(events).findings[0]
    assert finding.rule == "distributed_attack" and finding.user == "admin"
    assert finding.severity is Severity.HIGH


def test_root_login_is_reported_but_not_blocked():
    result = analyze([ok(0, "root", "198.51.100.20")])
    assert [f.rule for f in result.findings] == ["root_login"]
    assert result.offending_ips() == []


def test_findings_sorted_by_severity():
    events = [fail(i, f"ghost{i}", "192.0.2.50", invalid=True) for i in range(6)]
    events += [fail(100 + i, "svc", "203.0.113.9") for i in range(3)] + [ok(200, "svc", "203.0.113.9")]
    severities = [f.severity for f in analyze(events).findings]
    assert severities == sorted(severities, reverse=True)


def test_sample_log_end_to_end(tmp_path, capsys):
    blocklist = tmp_path / "block.txt"
    code = main([str(SAMPLE), "--year", "2026", "--format", "json", "--blocklist", str(blocklist)])
    assert code == 1  # hay hallazgos críticos
    report = json.loads(capsys.readouterr().out)
    found = {f["rule"] for f in report["findings"]}
    assert found == {
        "success_after_failures",
        "distributed_attack",
        "brute_force",
        "password_spraying",
        "root_login",
        "user_enumeration",
    }
    blocked = blocklist.read_text().split()
    assert "203.0.113.99" in blocked and "203.0.113.45" in blocked
    assert not any(ip.startswith("198.51.100.") for ip in blocked)  # el tráfico legítimo no se bloquea


def test_allowlist_is_respected(tmp_path, capsys):
    blocklist = tmp_path / "block.txt"
    main([str(SAMPLE), "--year", "2026", "--blocklist", str(blocklist), "--allow", "203.0.113.0/24"])
    capsys.readouterr()
    # 192.0.2.10-16 son la botnet del ataque distribuido de la muestra
    assert blocklist.read_text().split() == [f"192.0.2.{i}" for i in range(10, 17)] + ["192.0.2.200"]


def test_clean_log_exits_zero(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("Sep 25 10:00:00 srv sshd[1]: Accepted publickey for alice from 198.51.100.1 port 1 ssh2\n")
    assert main([str(log), "--year", "2026"]) == 0
    assert "Sin hallazgos" in capsys.readouterr().out
    assert main([str(log), "--year", "2026", "--format", "md"]) == 0
    assert "# Informe de log-sentinel" in capsys.readouterr().out


def test_text_report_lists_every_finding(capsys):
    assert main([str(SAMPLE), "--year", "2026"]) == 1
    out = capsys.readouterr().out
    assert out.count("CRÍTICA") == 1 and "T1110.003 Password Spraying" in out
    assert "IPs con más fallos:" in out


def test_missing_file_and_bad_cidr(tmp_path, capsys):
    assert main([str(tmp_path / "no-existe.log")]) == 2
    assert main([str(SAMPLE), "--allow", "no-es-una-red"]) == 2


def test_second_compromise_starts_at_its_own_failures():
    events = [fail(i, "root", "203.0.113.7") for i in range(3)] + [ok(60, "root", "203.0.113.7")]
    events += [fail(3600 + i, "root", "203.0.113.7") for i in range(3)] + [ok(3660, "root", "203.0.113.7")]
    found = [f for f in analyze(events).findings if f.rule == "success_after_failures"]
    assert len(found) == 2
    assert sorted(f.first_seen for f in found)[1] == T0 + timedelta(seconds=3600)


def test_failures_on_one_host_and_success_on_another_are_not_a_compromise():
    events = [
        AuthEvent(T0 + timedelta(seconds=i), "web1", EventKind.FAILED, "root", "198.51.100.3", "password")
        for i in range(3)
    ]
    events.append(AuthEvent(T0 + timedelta(seconds=30), "db1", EventKind.ACCEPTED, "root", "198.51.100.3", "publickey"))
    assert "success_after_failures" not in rules(events)


def test_distributed_attack_ips_go_to_the_blocklist():
    ips = [f"203.0.113.{i}" for i in range(1, 6)]
    analysis = analyze([fail(i, "admin", ip) for i, ip in enumerate(ips)])
    assert "distributed_attack" in {f.rule for f in analysis.findings}
    assert analysis.offending_ips() == sorted(ips)

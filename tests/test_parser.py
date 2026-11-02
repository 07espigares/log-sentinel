import gzip
from datetime import datetime

from logsentinel import EventKind, parse_lines
from logsentinel.parser import read_lines


def parse(*lines: str, year: int = 2026):
    return list(parse_lines(lines, year))


def test_failed_password_valid_and_invalid_user():
    events = parse(
        "Sep 25 10:00:01 srv sshd[100]: Failed password for root from 203.0.113.5 port 5000 ssh2",
        "Sep 25 10:00:02 srv sshd[101]: Failed password for invalid user oracle from 203.0.113.5 port 5001 ssh2",
    )
    assert [(e.kind, e.user, e.ip, e.invalid_user) for e in events] == [
        (EventKind.FAILED, "root", "203.0.113.5", False),
        (EventKind.FAILED, "oracle", "203.0.113.5", True),
    ]
    assert events[0].timestamp == datetime(2026, 9, 25, 10, 0, 1)


def test_accepted_and_invalid_user_lines():
    events = parse(
        "Sep  5 08:00:00 srv sshd[1]: Accepted publickey for alice from 198.51.100.1 port 22 ssh2: ED25519 SHA256:x",
        "Sep  5 08:00:05 srv sshd[2]: Invalid user test from 192.0.2.9 port 4000",
    )
    assert events[0].kind is EventKind.ACCEPTED and events[0].method == "publickey"
    assert events[0].timestamp.day == 5
    assert events[1].kind is EventKind.INVALID_USER and events[1].user == "test"


def test_iso_timestamps_and_sshd_session_process():
    events = parse(
        "2026-09-25T10:00:01.123456+02:00 srv sshd-session[9]: Failed password for bob from 2001:db8::1 port 1 ssh2",
        "2026-09-25T10:00:02Z srv sshd[9]: Failed password for bob from 192.0.2.1 port 1 ssh2",
        "2026-09-25T10:00:03.123+0200 srv sshd[9]: Failed password for bob from 192.0.2.1 port 1 ssh2",
    )
    assert len(events) == 3
    assert events[0].ip == "2001:db8::1"
    assert events[0].timestamp == datetime(2026, 9, 25, 10, 0, 1, 123456)
    assert events[2].timestamp.microsecond == 123000


def test_noise_and_corrupt_lines_are_ignored():
    events = parse(
        "Sep 25 10:00:00 srv CRON[1]: pam_unix(cron:session): session opened for user root",
        "Sep 25 10:00:00 srv sshd[1]: Connection closed by 192.0.2.1 port 22 [preauth]",
        "Feb 30 10:00:00 srv sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2",
        "basura sin formato",
        "",
    )
    assert events == []


def test_year_rollover_from_december_to_january():
    events = parse(
        "Dec 31 23:59:59 srv sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
        "Jan  1 00:00:01 srv sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
        year=2025,
    )
    assert [e.timestamp.year for e in events] == [2025, 2026]


def test_read_gzip_rotated_log(tmp_path):
    path = tmp_path / "auth.log.2.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write("Sep 25 10:00:01 srv sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\n")
    assert len(list(parse_lines(read_lines(path), 2026))) == 1


def test_year_is_guessed_from_today_when_not_given():
    line = "Dec 31 23:59:59 srv sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2"
    # Leído el 1 de enero, un "Dec 31" es del año anterior, no de dentro de un año.
    events = list(parse_lines([line], now=datetime(2027, 1, 1, 0, 5)))
    assert events[0].timestamp == datetime(2026, 12, 31, 23, 59, 59)
    events = list(parse_lines([line], now=datetime(2026, 12, 31, 23, 59, 59)))
    assert events[0].timestamp.year == 2026


def test_windows_line_endings():
    events = parse("Sep 25 10:00:01 srv sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\r\n")
    assert len(events) == 1 and events[0].ip == "192.0.2.1"


def test_rsyslog_repeated_message_counts_every_attempt():
    # Ubuntu trae "$RepeatedMsgReduction on": los fallos seguidos idénticos llegan en una sola línea.
    events = parse(
        "Oct 30 10:00:00 srv sshd[7]: Failed password for root from 203.0.113.5 port 22 ssh2",
        "Oct 30 10:00:09 srv sshd[7]: message repeated 4 times: "
        "[ Failed password for root from 203.0.113.5 port 22 ssh2]",
    )
    assert len(events) == 5
    assert all(e.kind is EventKind.FAILED and e.ip == "203.0.113.5" for e in events)


def test_repeated_message_with_absurd_count_is_capped():
    # Un log manipulado no puede hacer que se creen mil millones de eventos en memoria.
    events = parse(
        "Oct 30 10:00:09 srv sshd[7]: message repeated 999999999 times: "
        "[ Failed password for root from 203.0.113.5 port 22 ssh2]",
    )
    assert 1 <= len(events) <= 10_000

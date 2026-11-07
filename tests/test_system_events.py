"""Lo que pasa dentro de la máquina: sudo, su, cuentas nuevas y sondeos al puerto de SSH."""

from logsentinel import EventKind, Severity, analyze, parse_lines


def parse(*lines: str):
    return list(parse_lines(lines, 2026))


def rules(analysis):
    return [f.rule for f in analysis.findings]


# --- parser ---------------------------------------------------------------


def test_ssh_probes_from_scanners_are_events():
    events = parse(
        "Sep 25 10:00:01 srv sshd[1]: Did not receive identification string from 203.0.113.7 port 50000",
        "Sep 25 10:00:02 srv sshd[2]: banner exchange: Connection from 203.0.113.7 port 50001: invalid format",
        "Sep 25 10:00:03 srv sshd[3]: Unable to negotiate with 203.0.113.7 port 50002: no matching key exchange "
        "method found. Their offer: diffie-hellman-group1-sha1 [preauth]",
        "Sep 25 10:00:04 srv sshd[4]: Protocol major versions differ for 203.0.113.7 port 50003: SSH-2.0 vs. SSH-1.5",
    )
    assert [(e.kind, e.ip) for e in events] == [(EventKind.PROBE, "203.0.113.7")] * 4


def test_sudo_lines():
    events = parse(
        "Sep 25 10:00:01 srv sudo:     pepe : TTY=pts/0 ; PWD=/home/pepe ; USER=root ; COMMAND=/usr/bin/apt update",
        "Sep 25 10:00:02 srv sudo:   intruso : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; "
        "COMMAND=/bin/bash",
        "Sep 25 10:00:03 srv sudo:     pepe : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/pepe ; "
        "USER=root ; COMMAND=/bin/sh",
        "2026-09-25T10:00:04.000+02:00 srv sudo[812]:     ana : TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
    )
    assert [(e.kind, e.user) for e in events] == [
        (EventKind.SUDO, "pepe"),
        (EventKind.SUDO_DENIED, "intruso"),
        (EventKind.SUDO_FAILED, "pepe"),
        (EventKind.SUDO, "ana"),
    ]
    assert events[0].extra == "/usr/bin/apt update"
    assert events[2].count == 3


def test_failed_su():
    events = parse("Sep 25 10:00:01 srv su[77]: FAILED SU (to root) pepe on pts/0")
    assert [(e.kind, e.user, e.extra) for e in events] == [(EventKind.SUDO_FAILED, "pepe", "root")]


def test_account_creation_and_privileged_groups():
    events = parse(
        "Sep 25 10:00:01 srv useradd[90]: new user: name=soporte, UID=0, GID=0, home=/root, shell=/bin/bash, "
        "from=/dev/pts/0",
        "Sep 25 10:00:02 srv usermod[91]: add 'soporte' to group 'sudo'",
        "Sep 25 10:00:03 srv usermod[91]: add 'soporte' to shadow group 'sudo'",
        "Sep 25 10:00:04 srv gpasswd[92]: user web added by root to group wheel",
        "Sep 25 10:00:05 srv usermod[93]: add 'ana' to group 'audio'",
    )
    kinds = [(e.kind, e.user, e.extra) for e in events]
    assert kinds[0] == (EventKind.ACCOUNT_CREATED, "soporte", "UID=0")
    assert (EventKind.GROUP_ADDED, "soporte", "sudo") in kinds
    assert (EventKind.GROUP_ADDED, "web", "wheel") in kinds
    # la línea "shadow group" es la misma operación: no se cuenta dos veces
    assert sum(1 for k in kinds if k == (EventKind.GROUP_ADDED, "soporte", "sudo")) == 1


def test_attacker_controlled_text_does_not_break_the_parser():
    # "COMMAND=" lo escribe quien ejecuta sudo: puede traer cualquier cosa
    events = parse("Sep 25 10:00:01 srv sudo: pepe : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/echo ; USER=x")
    assert events[0].extra == "/bin/echo ; USER=x"


# --- detectores -----------------------------------------------------------


def test_scanner_probes_are_flagged():
    lines = [
        f"Sep 25 10:00:{i:02d} srv sshd[{i}]: Did not receive identification string from 203.0.113.7 port {5000 + i}"
        for i in range(5)
    ]
    analysis = analyze(parse(*lines))
    (finding,) = [f for f in analysis.findings if f.rule == "ssh_scan"]
    assert finding.ip == "203.0.113.7" and finding.severity is Severity.LOW
    assert finding.mitre.startswith("T1046")
    assert "203.0.113.7" in analysis.offending_ips()


def test_a_couple_of_probes_is_noise():
    lines = [
        "Sep 25 10:00:01 srv sshd[1]: Did not receive identification string from 203.0.113.7 port 5000",
        "Sep 25 10:00:02 srv sshd[2]: Did not receive identification string from 203.0.113.7 port 5001",
    ]
    assert "ssh_scan" not in rules(analyze(parse(*lines)))


def test_sudo_denied_is_flagged():
    analysis = analyze(
        parse(
            "Sep 25 10:00:02 srv sudo: intruso : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; "
            "USER=root ; COMMAND=/bin/bash"
        )
    )
    (finding,) = analysis.findings
    assert finding.rule == "sudo_denied" and finding.user == "intruso"
    assert finding.mitre.startswith("T1548.003")
    assert "/bin/bash" in finding.details


def test_repeated_sudo_and_su_failures_are_flagged():
    analysis = analyze(
        parse(
            "Sep 25 10:00:01 srv sudo: pepe : 2 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; "
            "COMMAND=/bin/sh",
            "Sep 25 10:00:05 srv su[7]: FAILED SU (to root) pepe on pts/0",
        )
    )
    (finding,) = analysis.findings
    assert finding.rule == "privilege_guessing" and finding.count == 3


def test_one_wrong_sudo_password_is_not_an_attack():
    analysis = analyze(
        parse(
            "Sep 25 10:00:01 srv sudo: pepe : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/ ; "
            "USER=root ; COMMAND=/bin/ls"
        )
    )
    assert analysis.findings == []


def test_new_accounts_and_admin_groups():
    analysis = analyze(
        parse(
            "Sep 25 10:00:01 srv useradd[90]: new user: name=soporte, UID=0, GID=0, home=/root, shell=/bin/bash",
            "Sep 25 10:00:02 srv useradd[91]: new user: name=ana, UID=1001, GID=1001, home=/home/ana, shell=/bin/bash",
            "Sep 25 10:00:03 srv usermod[92]: add 'ana' to group 'sudo'",
            "Sep 25 10:00:04 srv usermod[93]: add 'ana' to group 'audio'",
        )
    )
    by_user = {(f.rule, f.user): f for f in analysis.findings}
    assert by_user[("account_created", "soporte")].severity is Severity.CRITICAL  # UID 0 = otro root
    assert by_user[("account_created", "ana")].severity is Severity.MEDIUM
    assert by_user[("admin_group", "ana")].severity is Severity.HIGH
    assert by_user[("admin_group", "ana")].mitre.startswith("T1098")
    assert ("admin_group", "ana") in by_user and len([f for f in analysis.findings if f.rule == "admin_group"]) == 1


def test_local_events_do_not_count_as_ssh_failures():
    analysis = analyze(parse("Sep 25 10:00:01 srv sudo: pepe : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"))
    assert analysis.failures == [] and analysis.offending_ips() == []

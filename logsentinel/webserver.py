"""Análisis de logs de nginx y Apache en el formato combined (el que traen por defecto).

    198.51.100.9 - - [25/Sep/2026:10:15:32 +0200] "GET /?id=1 HTTP/1.1" 200 512 "-" "curl/8"

Busca cargas de ataque en las peticiones (inyección SQL, path traversal, ejecución de
comandos, XSS) y escaneos de rutas. Devuelve los mismos `Finding` que el análisis de
SSH, así que los informes, el panel y los avisos sirven para los dos.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import unquote_plus

from .detectors import Config, Finding, Severity
from .parser import MONTHS

LINE = re.compile(
    # (?:host:puerto )? es el formato vhost_combined de Apache (other_vhosts_access.log)
    r"^(?:\S+:\d+ )?(?P<ip>[0-9a-fA-F.:]+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)
TIME = re.compile(r"(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})")

# ;id  |cat /etc/passwd  $(whoami)  `uname -a`  && wget ...
CMD_INJECTION = re.compile(
    r"(?:[;|`]|&&|\$\()\s*(?:id|whoami|uname|cat|ls|pwd|wget|curl|nc|ncat|bash|sh|python[0-9.]*|perl|sleep|ping)\b"
)


@dataclass(frozen=True)
class Signature:
    severity: Severity
    title: str
    mitre: str
    needles: tuple[str, ...]
    regex: re.Pattern | None = None

    def matches(self, text: str) -> bool:
        return any(n in text for n in self.needles) or bool(self.regex and self.regex.search(text))


# Se buscan sobre el texto ya normalizado (ver normalize), todo en minúsculas.
SIGNATURES = {
    "sqli": Signature(
        Severity.HIGH,
        "Inyección SQL",
        "T1190 Exploit Public-Facing Application",
        (
            "union select",
            "union all select",
            "' or '",
            '" or "',
            " or 1=1",
            " or 1 = 1",
            "' and '1'='1",
            "information_schema",
            "sleep(",
            "benchmark(",
            "pg_sleep",
            "waitfor delay",
            "group_concat",
            "load_file(",
            "into outfile",
            "xp_cmdshell",
        ),
    ),
    "path_traversal": Signature(
        Severity.HIGH,
        "Path traversal / lectura de ficheros",
        "T1083 File and Directory Discovery",
        ("../", "..\\", "/etc/passwd", "/etc/shadow", "boot.ini", "/proc/self/environ", "\x00"),
    ),
    "rce": Signature(
        Severity.CRITICAL,
        "Intento de ejecución de comandos",
        "T1190 Exploit Public-Facing Application",
        ("${jndi:", "() {", "/bin/sh", "/bin/bash", "nc -e", "cmd.exe", "powershell"),
        CMD_INJECTION,
    ),
    "xss": Signature(
        Severity.MEDIUM,
        "Cross-site scripting (XSS)",
        "T1059.007 JavaScript",
        ("<script", "onerror=", "onload=", "javascript:", "alert(", "<img ", "<svg "),
    ),
}

# Rutas que un visitante normal no pide nunca. Si alguien pide varias, está buscando fallos.
SENSITIVE_PATHS = (
    "/.env",
    "/.git/",
    "/.svn/",
    "/.aws/",
    "/.ssh/",
    "/wp-admin",
    "/wp-login.php",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/administrator",
    "/config.php",
    "/server-status",
    "/actuator",
    "/solr/",
    "/struts",
    "/cgi-bin/",
    "/shell",
    "/backup.sql",
    "/.htpasswd",
    "/vendor/phpunit",
    "/console",
)


# Búsquedas de Log4j que sirven para ofuscar Log4Shell: ${lower:j}, ${upper:j}, ${::-j},
# ${env:NO_EXISTE:-j}... Al resolverlas, "${${lower:j}ndi:" queda en "${jndi:".
LOG4J_LOOKUP = re.compile(r"\$\{(?:(?:lower|upper):|[a-z]*:[^:{}$]*:-)([^{}$]*)\}")


LOG_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})|\\[\"\\]")


def _resolve_log4j_lookups(text: str) -> str:
    for _ in range(10):
        resolved = LOG4J_LOOKUP.sub(r"\1", text)
        if resolved == text:
            break
        text = resolved
    return text


def normalize(text: str) -> str:
    """Deja la petición como la acabaría viendo la aplicación, para buscar firmas en ella.

    - Descodifica %xx hasta tres veces: con doble codificación (%252e -> %2e -> .)
      se saltan los filtros que solo descodifican una vez.
    - El '+' de la query string es un espacio: ?id=1+union+select.
    - Los comentarios SQL /**/ hacen de espacio: union/**/select.
    """
    # nginx escribe los bytes raros y las comillas como \xHH y Apache como \" en el log.
    text = LOG_ESCAPE.sub(lambda m: chr(int(m[1], 16)) if m[1] else m[0][1], text)
    for _ in range(3):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    text = text.lower().replace("/**/", " ")
    if "${" in text:
        text = _resolve_log4j_lookups(text)
    return " ".join(text.split())


@dataclass(frozen=True)
class WebEvent:
    timestamp: datetime
    ip: str
    method: str
    path: str
    status: int
    size: int
    user_agent: str
    raw_request: str


def _parse_time(text: str) -> datetime | None:
    m = TIME.search(text)
    if not m:
        return None
    day, mon, year, hh, mm, ss = m.groups()
    month = MONTHS.get(mon)
    if month is None:
        return None
    try:
        return datetime(int(year), month, int(day), int(hh), int(mm), int(ss))
    except ValueError:
        return None


def parse_web_lines(lines: Iterable[str], year: int | None = None) -> Iterator[WebEvent]:
    """Convierte líneas del log en `WebEvent`. Las que no encajan se ignoran.

    `year` no se usa (aquí la fecha ya lleva el año); está para que la firma sea la
    misma que la de `parse_lines` y el resto del programa pueda usar las dos igual.
    """
    for line in lines:
        m = LINE.match(line.rstrip("\r\n"))
        if not m:
            continue
        timestamp = _parse_time(m["time"])
        if timestamp is None:
            continue
        request = m["req"]
        parts = request.split(" ")
        yield WebEvent(
            timestamp=timestamp,
            ip=m["ip"],
            method=parts[0],
            path=parts[1] if len(parts) > 1 else request,
            status=int(m["status"]),
            size=0 if m["size"] == "-" else int(m["size"]),
            user_agent=m["ua"] or "",
            raw_request=request,
        )


@dataclass
class WebAnalysis:
    events: list[WebEvent]
    findings: list[Finding] = field(default_factory=list)

    def top_ips(self, n: int = 10) -> list[tuple[str, int]]:
        return Counter(e.ip for e in self.events).most_common(n)

    def top_paths(self, n: int = 10) -> list[tuple[str, int]]:
        return Counter(e.path for e in self.events if e.status in (404, 403)).most_common(n)

    def offending_ips(self) -> list[str]:
        return sorted({f.ip for f in self.findings if f.ip})


def _signature_findings(events: list[WebEvent]) -> list[Finding]:
    # (ip, regla) -> [(evento, ejemplo)]
    hits: dict[tuple[str, str], list[tuple[WebEvent, str]]] = defaultdict(list)
    for event in events:
        request = normalize(event.raw_request)
        # Log4Shell y Shellshock suelen venir en el User-Agent, no en la URL.
        user_agent = normalize(event.user_agent)
        for rule, sig in SIGNATURES.items():
            if sig.matches(request):
                hits[(event.ip, rule)].append((event, f"{event.method} {event.path}"))
            elif sig.matches(user_agent):
                hits[(event.ip, rule)].append((event, f"User-Agent: {event.user_agent}"))

    findings = []
    for (ip, rule), matches in hits.items():
        sig = SIGNATURES[rule]
        first, example = matches[0]
        findings.append(
            Finding(
                sig.severity,
                rule,
                f"{sig.title} desde {ip}",
                first.timestamp,
                matches[-1][0].timestamp,
                len(matches),
                ip=ip,
                mitre=sig.mitre,
                details=f"{len(matches)} petición(es) sospechosa(s). Ejemplo: {example[:100]}",
            )
        )
    return findings


def _is_sensitive(path: str) -> bool:
    return any(s in path for s in SENSITIVE_PATHS)


def _scanner_findings(events: list[WebEvent], cfg: Config) -> list[Finding]:
    by_ip: dict[str, list[WebEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.ip].append(event)

    findings = []
    for ip, evs in by_ip.items():
        # normalize() una vez por petición, no una vez por cada ruta sensible
        # (sin la query: /wp-admin?x=1 y ?x=2 son la misma ruta, y ?q=/.env no es pedir /.env)
        paths = {normalize(e.path.split("?", 1)[0]) for e in evs}
        sensitive = {p for p in paths if _is_sensitive(p)}
        not_found = {e.path for e in evs if e.status == 404}
        if len(sensitive) >= cfg.web_scanner_min_sensitive:
            sample = ", ".join(sorted(sensitive)[:5])
            findings.append(
                Finding(
                    Severity.MEDIUM,
                    "recon_scanner",
                    f"Escaneo de rutas sensibles desde {ip}",
                    evs[0].timestamp,
                    evs[-1].timestamp,
                    len(sensitive),
                    ip=ip,
                    mitre="T1595.003 Wordlist Scanning",
                    details=f"{len(sensitive)} rutas que no existen en una web normal: {sample}",
                )
            )
        elif len(not_found) >= cfg.web_scanner_min_404:
            findings.append(
                Finding(
                    Severity.LOW,
                    "path_bruteforce",
                    f"Barrido de rutas (muchos 404) desde {ip}",
                    evs[0].timestamp,
                    evs[-1].timestamp,
                    len(not_found),
                    ip=ip,
                    mitre="T1595 Active Scanning",
                    details=f"{len(not_found)} rutas distintas devolvieron 404, parece un escáner automático",
                )
            )
    return findings


def analyze_web(events: list[WebEvent], cfg: Config | None = None) -> WebAnalysis:
    cfg = cfg or Config()
    events = sorted(events, key=lambda e: e.timestamp)
    result = WebAnalysis(events)
    result.findings.extend(_signature_findings(events))
    result.findings.extend(_scanner_findings(events, cfg))
    result.findings.sort(key=lambda f: (-f.severity, f.first_seen))
    return result

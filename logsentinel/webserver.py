"""Análisis de logs de nginx y Apache en el formato combined (el que traen por defecto).

    198.51.100.9 - - [25/Sep/2026:10:15:32 +0200] "GET /?id=1 HTTP/1.1" 200 512 "-" "curl/8"

Busca cargas de ataque en las peticiones (inyección SQL, path traversal, ejecución de
comandos, XSS, SSRF, inclusión de ficheros, inyección de plantillas, webshells),
herramientas de ataque por su User-Agent, fuerza bruta contra formularios de login y
escaneos de rutas. Devuelve los mismos `Finding` que el análisis de
SSH, así que los informes, el panel y los avisos sirven para los dos.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import unquote_plus

from .detectors import Config, Finding, Severity, _max_distinct_in_window, _max_in_window
from .parser import MONTHS

LINE = re.compile(
    # (?:host:puerto )? es el formato vhost_combined de Apache (other_vhosts_access.log)
    r"^(?:\S+:\d+ )?(?P<ip>[0-9a-fA-F.:]+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)
TIME = re.compile(r"(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})")

# ;id  |cat /etc/passwd  $(whoami)  `uname -a`  && wget ...
# Dentro de $( ) o de comillas invertidas, cualquier orden. Detrás de ; | o &&, depende: las que
# también son palabras o valores normales (cat, sleep, perl...) solo cuentan si llevan un argumento,
# porque ?animales=perro|cat o ?emisoras=rock;sleep;jazz no son ataques, y ;id=5 es un parámetro.
CMD_INJECTION = re.compile(
    r"(?:\$\(|`)\s*(?:id|whoami|uname|cat|ls|pwd|wget|curl|nc|ncat|bash|sh|python[0-9.]*|perl|sleep|ping)\b"
    r"|(?:[;|]|&&)\s*(?:id|whoami|uname|pwd|ls)\b(?![=\w-])"
    r"|(?:[;|]|&&)\s*(?:cat|wget|curl|nc|ncat|bash|sh|python[0-9.]*|perl|sleep|ping)\s+(?!http/\d)[^\s;|&]"
)
# and 5231=5231, or (8=8, and 2*3=6: las comprobaciones de verdadero/falso de sqlmap y compañía;
# ;drop table (varias órdenes seguidas); order by 9-- (contar columnas); y la comilla que cierra
# el texto seguida de un comentario.
SQLI = re.compile(
    r"\b(?:and|or)\s+\(?\s*\d+(?:\s*[*+-]\s*\d+)?\s*=\s*\d+"
    r"|;\s*(?:drop|insert|update|delete|create|alter|truncate|exec)\s+\w"
    r"|\border\s+by\s+\d+\s*(?:--|#|/\*)"
    r"|'\s*--"
)


# /uploads/c99.php, /wso.php... o cualquier .php/.jsp/.asp que recibe ?cmd= o ?exec=
WEBSHELL = re.compile(
    r"/(?:c99|r57|wso|b374k|alfa|webshell|sh3ll|shell)[\w.-]*\.(?:php\d?|phtml|jspx?|aspx?)\b"
    r"|\.(?:php\d?|phtml|jspx?|aspx?)\?(?:[^ ]*&)?(?:cmd|exec|command|execute)="
)
# {{7*7}}, ${7*7}, #{7*7}: la prueba de siempre para ver si la plantilla evalúa lo que mandas
SSTI = re.compile(r"(?:\{\{|\$\{|#\{)\s*\d+\s*[*+]\s*\d+\s*\}|\{\{\s*(?:config|self|request)\b")

# Herramientas de ataque que se anuncian en el User-Agent. Un atacante cuidadoso lo cambia,
# pero muchos escaneos automáticos no se molestan.
SCANNER_TOOLS = (
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei", "wpscan", "dirbuster", "gobuster",
    "feroxbuster", "ffuf", "fuzz faster", "wfuzz", "acunetix", "nessus", "openvas", "jaeles",
    "hydra", "netsparker", "arachni", "whatweb", "commix",
)  # fmt: skip
# Formularios de login a los que apuntan los ataques de fuerza bruta web.
LOGIN_PATHS = re.compile(
    r"^/(?:wp-login\.php|xmlrpc\.php|login|signin|sign-in|user/login|users/sign_in|admin/login|"
    r"administrator/index\.php|api/(?:v\d+/)?(?:auth|login)|auth/login|session)(?:[/?.]|$)"
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
            "@@version",
        ),
        SQLI,
    ),
    "path_traversal": Signature(
        Severity.HIGH,
        "Path traversal / lectura de ficheros",
        "T1083 File and Directory Discovery",
        # "..;/" engaña a Tomcat detrás de un proxy; "....//" queda en "../" si un filtro borra "../" una vez
        ("../", "..\\", "..;/", "....//", "/etc/passwd", "/etc/shadow", "boot.ini", "/proc/self/environ", "\x00"),
    ),
    "rce": Signature(
        Severity.CRITICAL,
        "Intento de ejecución de comandos",
        "T1190 Exploit Public-Facing Application",
        # class.module.classloader es Spring4Shell (CVE-2022-22965)
        ("${jndi:", "() {", "/bin/sh", "/bin/bash", "nc -e", "cmd.exe", "powershell", "class.module.classloader"),
        CMD_INJECTION,
    ),
    "webshell": Signature(
        Severity.CRITICAL,
        "Uso de una webshell",
        "T1505.003 Web Shell",
        (),
        WEBSHELL,
    ),
    "ssrf": Signature(
        Severity.HIGH,
        "SSRF (el servidor pide URLs por el atacante)",
        "T1190 Exploit Public-Facing Application",
        # 169.254.169.254 y metadata.google.internal dan las credenciales de la nube
        ("169.254.169.254", "metadata.google.internal", "100.100.100.200", "gopher://", "dict://", "file:///"),
    ),
    "file_inclusion": Signature(
        Severity.HIGH,
        "Inclusión de ficheros (LFI con envoltorios de PHP)",
        "T1190 Exploit Public-Facing Application",
        ("php://filter", "php://input", "data://text", "expect://", "phar://", "zip://"),
    ),
    "ssti": Signature(
        Severity.HIGH,
        "Inyección de plantillas (SSTI)",
        "T1190 Exploit Public-Facing Application",
        ("__class__", "__globals__", "__builtins__", "__subclasses__", "<%=", "{{config", "{{self", "{{request"),
        SSTI,
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
# "/" , "." y "\\" escritos en UTF-8 con más bytes de la cuenta: no son válidos, pero algunos
# servidores viejos los aceptan y así se cuela un "../" que ningún filtro ve.
OVERLONG = re.compile(r"%c0%af|%c0%ae|%c1%9c|%e0%80%af", re.IGNORECASE)
OVERLONG_CHARS = {"%c0%af": "/", "%c0%ae": ".", "%c1%9c": "\\", "%e0%80%af": "/"}


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
        text = OVERLONG.sub(lambda m: OVERLONG_CHARS[m[0].lower()], text)
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
        # Un 200 no prueba que el ataque funcionara, pero es lo primero que hay que mirar.
        ok = sum(1 for event, _ in matches if 200 <= event.status < 300)
        answered = f" {ok} respondida{'s' if ok != 1 else ''} con 200: revisa esas primero." if ok else ""
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
                details=f"{len(matches)} petición(es) sospechosa(s). Ejemplo: {example[:100]}.{answered}",
            )
        )
    return findings


def _tool_findings(events: list[WebEvent]) -> list[Finding]:
    by_ip: dict[str, list[tuple[WebEvent, str]]] = defaultdict(list)
    for event in events:
        ua = event.user_agent.lower()
        tool = next((t for t in SCANNER_TOOLS if t in ua), None)
        if tool:
            by_ip[event.ip].append((event, tool))
    findings = []
    for ip, hits in by_ip.items():
        tools = sorted({tool for _, tool in hits})
        findings.append(
            Finding(
                Severity.MEDIUM,
                "scanner_tool",
                f"Herramienta de ataque ({', '.join(tools)}) desde {ip}",
                hits[0][0].timestamp,
                hits[-1][0].timestamp,
                len(hits),
                ip=ip,
                mitre="T1595.002 Vulnerability Scanning",
                details=f"{len(hits)} petición(es) con el User-Agent de {', '.join(tools)}",
            )
        )
    return findings


def _login_bruteforce_findings(events: list[WebEvent], cfg: Config) -> list[Finding]:
    by_ip: dict[str, list[WebEvent]] = defaultdict(list)
    for event in events:
        if event.method == "POST" and LOGIN_PATHS.match(event.path.lower()):
            by_ip[event.ip].append(event)
    findings = []
    for ip, posts in by_ip.items():
        count, start, end = _max_in_window([e.timestamp for e in posts], cfg.window)
        if count >= cfg.brute_force_threshold:
            paths = Counter(e.path.split("?", 1)[0] for e in posts)
            target, _ = paths.most_common(1)[0]
            findings.append(
                Finding(
                    Severity.MEDIUM,
                    "web_login_bruteforce",
                    f"Fuerza bruta contra {target} desde {ip}",
                    start,
                    end,
                    count,
                    ip=ip,
                    mitre="T1110.001 Password Guessing",
                    details=(
                        f"{count} intentos de login en {int(cfg.window.total_seconds() // 60)} min "
                        f"({len(posts)} en total). WordPress responde 200 aunque la contraseña esté mal"
                    ),
                )
            )
    return findings


# De las rutas sensibles, las que son archivos con secretos dentro: nadie debería poder bajarlos.
SECRET_FILES = ("/.env", "/.git/", "/.svn/", "/.aws/", "/.ssh/", "/.htpasswd", "/backup.sql")


def _is_sensitive(path: str) -> bool:
    return any(s in path for s in SENSITIVE_PATHS)


def _is_secret(path: str) -> bool:
    return any(s in path for s in SECRET_FILES)


def _exposed_findings(events: list[WebEvent]) -> list[Finding]:
    """Un archivo con secretos (.env, .git/config...) que el servidor ha entregado con un 200.

    Es lo más grave que puede salir de un escaneo: ya no es alguien probando, es que lo que
    buscaba estaba ahí. Las webs que contestan 200 a cualquier ruta con la misma página (muchas
    aplicaciones de una sola página) no cuentan: se reconocen porque todo mide lo mismo.
    """
    paths_by_size: dict[int, set[str]] = defaultdict(set)
    for e in events:
        if e.status == 200:
            paths_by_size[e.size].add(e.path.split("?", 1)[0])
    by_ip: dict[str, list[WebEvent]] = defaultdict(list)
    for e in events:
        path = normalize(e.path.split("?", 1)[0])
        if e.status == 200 and e.size > 0 and _is_secret(path) and len(paths_by_size[e.size]) < 3:
            by_ip[e.ip].append(e)
    findings = []
    for ip, evs in by_ip.items():
        paths = sorted({e.path.split("?", 1)[0] for e in evs})
        findings.append(
            Finding(
                Severity.HIGH,
                "exposed_file",
                f"Archivo con secretos entregado a {ip}",
                evs[0].timestamp,
                evs[-1].timestamp,
                len(evs),
                ip=ip,
                mitre="T1552.001 Credentials In Files",
                details=(
                    f"el servidor respondió 200 a {', '.join(paths[:5])}. Comprueba qué hay ahí; si son "
                    "contraseñas o claves, dalas por robadas y cámbialas"
                ),
            )
        )
    return findings


def _scanner_findings(events: list[WebEvent], cfg: Config) -> list[Finding]:
    by_ip: dict[str, list[WebEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.ip].append(event)

    findings = []
    for ip, evs in by_ip.items():
        # normalize() una vez por petición, no una vez por cada ruta sensible
        # (sin la query: /wp-admin?x=1 y ?x=2 son la misma ruta, y ?q=/.env no es pedir /.env)
        # Un panel de administración que existe y contesta (el dueño entrando en su /wp-admin) no
        # es un escaneo. Cuentan los que dan error, que es lo que se encuentra quien prueba a
        # ciegas, y los archivos con secretos, que nadie tiene por qué pedir.
        sensitive = set()
        for e in evs:
            path = normalize(e.path.split("?", 1)[0])
            if _is_sensitive(path) and (e.status >= 400 or _is_secret(path)):
                sensitive.add(path)
        misses = [(e.timestamp, e.path) for e in evs if e.status == 404]
        not_found: set[str] = set()
        if misses:
            # En pocos minutos: un buscador que va encontrando enlaces rotos durante días no es un escáner.
            count, start, end = _max_distinct_in_window(misses, cfg.web_scanner_window)
            if count >= cfg.web_scanner_min_404:
                not_found = {path for moment, path in misses if start <= moment <= end}
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
    result.findings.extend(_exposed_findings(events))
    result.findings.extend(_scanner_findings(events, cfg))
    result.findings.extend(_tool_findings(events))
    result.findings.extend(_login_bruteforce_findings(events, cfg))
    result.findings.sort(key=lambda f: (-f.severity, f.first_seen))
    return result

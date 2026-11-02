"""Reglas de detección sobre los eventos de autenticación.

Cada regla produce hallazgos con severidad y, cuando aplica, la técnica de MITRE ATT&CK.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum

from .parser import AuthEvent, EventKind


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {1: "BAJA", 2: "MEDIA", 3: "ALTA", 4: "CRÍTICA"}[self.value]


@dataclass
class Finding:
    severity: Severity
    rule: str
    title: str
    first_seen: datetime
    last_seen: datetime
    count: int
    ip: str | None = None
    user: str | None = None
    mitre: str | None = None
    details: str = ""
    # IPs que participan en un ataque repartido entre muchas (ataque distribuido)
    related_ips: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.label,
            "rule": self.rule,
            "title": self.title,
            "ip": self.ip,
            "user": self.user,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "mitre": self.mitre,
            "details": self.details,
            "related_ips": list(self.related_ips),
        }


@dataclass(frozen=True)
class Config:
    brute_force_threshold: int = 10  # fallos desde una IP...
    window: timedelta = timedelta(minutes=5)  # ...dentro de esta ventana
    spray_min_users: int = 5  # usuarios distintos desde una IP
    spray_max_attempts_per_user: float = 3.0  # pocos intentos por usuario = spraying, no fuerza bruta
    enumeration_min_users: int = 5  # usuarios inexistentes distintos desde una IP
    distributed_min_ips: int = 5  # IPs distintas contra la misma cuenta
    failures_before_success: int = 3  # fallos previos que hacen sospechoso un acceso correcto
    # Logs web (ver webserver.py):
    web_scanner_min_sensitive: int = 3  # rutas sensibles distintas desde una IP -> escaneo
    web_scanner_min_404: int = 20  # rutas distintas con 404 desde una IP -> barrido


@dataclass
class Analysis:
    events: list[AuthEvent]
    findings: list[Finding] = field(default_factory=list)

    @property
    def failures(self) -> list[AuthEvent]:
        return [e for e in self.events if e.kind is EventKind.FAILED]

    @property
    def successes(self) -> list[AuthEvent]:
        return [e for e in self.events if e.kind is EventKind.ACCEPTED]

    def top_ips(self, n: int = 10) -> list[tuple[str, int]]:
        return Counter(e.ip for e in self.failures).most_common(n)

    def top_users(self, n: int = 10) -> list[tuple[str, int]]:
        return Counter(e.user for e in self.failures).most_common(n)

    def offending_ips(self) -> list[str]:
        """IPs atacantes (para una lista de bloqueo). No incluye accesos legítimos de root."""
        rules = {"brute_force", "password_spraying", "user_enumeration", "success_after_failures"}
        ips = {f.ip for f in self.findings if f.ip and f.rule in rules}
        ips.update(ip for f in self.findings if f.rule == "distributed_attack" for ip in f.related_ips)
        return sorted(ips)


def _max_in_window(times: list[datetime], window: timedelta) -> tuple[int, datetime, datetime]:
    """Máximo número de eventos dentro de cualquier ventana deslizante (dos punteros, O(n))."""
    best, best_start, best_end = 0, times[0], times[0]
    start = 0
    for end, t in enumerate(times):
        while t - times[start] > window:
            start += 1
        if end - start + 1 > best:
            best, best_start, best_end = end - start + 1, times[start], t
    return best, best_start, best_end


def detect_brute_force(events: list[AuthEvent], cfg: Config) -> list[Finding]:
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        if e.kind is EventKind.FAILED:
            by_ip[e.ip].append(e)
    findings = []
    for ip, fails in by_ip.items():
        count, start, end = _max_in_window([e.timestamp for e in fails], cfg.window)
        if count >= cfg.brute_force_threshold:
            users = Counter(e.user for e in fails)
            main_user, _ = users.most_common(1)[0]
            findings.append(
                Finding(
                    Severity.MEDIUM,
                    "brute_force",
                    f"Fuerza bruta desde {ip}",
                    start,
                    end,
                    count,
                    ip=ip,
                    user=main_user if len(users) == 1 else None,
                    mitre="T1110.001 Password Guessing",
                    details=(
                        f"{count} fallos en {int(cfg.window.total_seconds() // 60)} min "
                        f"({len(fails)} en total, {len(users)} usuario(s); el más atacado: {main_user})"
                    ),
                )
            )
    return findings


def detect_password_spraying(events: list[AuthEvent], cfg: Config) -> list[Finding]:
    # Solo cuentan las cuentas que existen: probar nombres inexistentes es enumeración, no spraying.
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        if e.kind is EventKind.FAILED and not e.invalid_user:
            by_ip[e.ip].append(e)
    findings = []
    for ip, fails in by_ip.items():
        users = {e.user for e in fails}
        if len(users) >= cfg.spray_min_users and len(fails) / len(users) <= cfg.spray_max_attempts_per_user:
            findings.append(
                Finding(
                    Severity.MEDIUM,
                    "password_spraying",
                    f"Password spraying desde {ip}",
                    fails[0].timestamp,
                    fails[-1].timestamp,
                    len(fails),
                    ip=ip,
                    mitre="T1110.003 Password Spraying",
                    details=f"{len(users)} cuentas existentes con {len(fails) / len(users):.1f} intentos de media",
                )
            )
    return findings


def detect_user_enumeration(events: list[AuthEvent], cfg: Config) -> list[Finding]:
    invalid: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        if e.invalid_user:
            invalid[e.ip].append(e)
    findings = []
    for ip, evs in invalid.items():
        names = sorted({e.user for e in evs})
        if len(names) >= cfg.enumeration_min_users:
            sample = ", ".join(names[:8]) + (", …" if len(names) > 8 else "")
            findings.append(
                Finding(
                    Severity.LOW,
                    "user_enumeration",
                    f"Prueba de usuarios inexistentes desde {ip}",
                    evs[0].timestamp,
                    evs[-1].timestamp,
                    len(names),
                    ip=ip,
                    details=f"{len(names)} nombres que no existen en el sistema: {sample}",
                )
            )
    return findings


def detect_distributed_attack(events: list[AuthEvent], cfg: Config) -> list[Finding]:
    by_user: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        if e.kind is EventKind.FAILED and not e.invalid_user:
            by_user[e.user].append(e)
    findings = []
    for user, fails in by_user.items():
        ips = {e.ip for e in fails}
        if len(ips) >= cfg.distributed_min_ips:
            findings.append(
                Finding(
                    Severity.HIGH,
                    "distributed_attack",
                    f"Ataque distribuido contra la cuenta '{user}'",
                    fails[0].timestamp,
                    fails[-1].timestamp,
                    len(fails),
                    user=user,
                    mitre="T1110 Brute Force",
                    details=f"{len(fails)} fallos desde {len(ips)} IPs distintas (típico de una botnet)",
                    related_ips=tuple(sorted(ips)),
                )
            )
    return findings


def detect_success_after_failures(events: list[AuthEvent], cfg: Config) -> list[Finding]:
    # Por máquina y por IP: fallar en un servidor y entrar en otro no es una contraseña adivinada.
    failures: Counter[tuple[str, str]] = Counter()
    first_failure: dict[tuple[str, str], datetime] = {}
    findings = []
    for e in events:
        key = (e.host, e.ip)
        if e.kind is EventKind.FAILED:
            failures[key] += 1
            first_failure.setdefault(key, e.timestamp)
        elif e.kind is EventKind.ACCEPTED and failures[key] >= cfg.failures_before_success:
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    "success_after_failures",
                    f"Acceso correcto de '{e.user}' desde {e.ip} tras {failures[key]} fallos",
                    first_failure[key],
                    e.timestamp,
                    failures[key],
                    ip=e.ip,
                    user=e.user,
                    mitre="T1078 Valid Accounts",
                    details=(
                        f"método: {e.method}. Posible credencial adivinada: comprueba la sesión, "
                        "cambia la contraseña y revisa qué se hizo con esa cuenta"
                    ),
                )
            )
            failures[key] = 0  # un solo aviso por racha de fallos
            first_failure.pop(key, None)  # la racha siguiente empieza en su primer fallo
    return findings


def detect_root_login(events: list[AuthEvent], cfg: Config) -> list[Finding]:
    roots = [e for e in events if e.kind is EventKind.ACCEPTED and e.user == "root"]
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in roots:
        by_ip[e.ip].append(e)
    return [
        Finding(
            Severity.MEDIUM,
            "root_login",
            f"Inicio de sesión directo como root desde {ip}",
            evs[0].timestamp,
            evs[-1].timestamp,
            len(evs),
            ip=ip,
            user="root",
            mitre="T1078.003 Local Accounts",
            details="buena práctica: PermitRootLogin no en sshd_config y usar sudo con un usuario personal",
        )
        for ip, evs in by_ip.items()
    ]


DETECTORS = [
    detect_success_after_failures,
    detect_distributed_attack,
    detect_brute_force,
    detect_password_spraying,
    detect_root_login,
    detect_user_enumeration,
]


def analyze(events: list[AuthEvent], cfg: Config | None = None) -> Analysis:
    cfg = cfg or Config()
    events = sorted(events, key=lambda e: e.timestamp)
    result = Analysis(events)
    for detector in DETECTORS:
        result.findings.extend(detector(events, cfg))
    result.findings.sort(key=lambda f: (-f.severity, f.first_seen))
    return result

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
    distributed_min_ips: int = 5  # IPs distintas contra la misma cuenta...
    distributed_window: timedelta = timedelta(days=1)  # ...en este tiempo (una botnet no tarda meses)
    failures_before_success: int = 3  # fallos previos que hacen sospechoso un acceso correcto
    scan_min_probes: int = 5  # conexiones al puerto 22 sin intentar entrar, desde una IP
    privilege_failures: int = 3  # contraseñas mal en sudo/su del mismo usuario
    # Logs web (ver webserver.py):
    web_scanner_min_sensitive: int = 3  # rutas sensibles distintas desde una IP -> escaneo
    web_scanner_min_404: int = 20  # rutas distintas con 404 desde una IP -> barrido...
    web_scanner_window: timedelta = timedelta(minutes=10)  # ...en este tiempo


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
        rules = {"brute_force", "password_spraying", "user_enumeration", "success_after_failures", "ssh_scan"}
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


def _max_distinct_in_window(events: list[tuple[datetime, object]], window: timedelta) -> tuple[int, datetime, datetime]:
    """Máximo de valores distintos dentro de cualquier ventana deslizante."""
    counts: Counter = Counter()
    best, span, start = 0, (events[0][0], events[0][0]), 0
    for moment, value in events:
        counts[value] += 1
        while moment - events[start][0] > window:
            old = events[start][1]
            counts[old] -= 1
            if not counts[old]:
                del counts[old]
            start += 1
        if len(counts) > best:
            best, span = len(counts), (events[start][0], moment)
    return best, *span


def detect_brute_force(events: list[AuthEvent], cfg: Config) -> list[Finding]:
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        # PREAUTH: en un servidor de solo llaves, cada intento acaba en un corte antes de identificarse.
        if e.kind in (EventKind.FAILED, EventKind.PREAUTH):
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
        # Dentro de un día: fallar la contraseña desde cinco sitios a lo largo de meses es una
        # persona que viaja, no una botnet.
        count, start, end = _max_distinct_in_window([(e.timestamp, e.ip) for e in fails], cfg.distributed_window)
        if count >= cfg.distributed_min_ips:
            fails = [e for e in fails if start <= e.timestamp <= end]
            ips = {e.ip for e in fails}
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
        elif e.kind is EventKind.ACCEPTED and failures[key] < cfg.failures_before_success:
            # Entró bien con pocos fallos: la racha se acaba aquí. Si no, tres erratas en tres
            # semanas distintas acababan sumando un "acceso tras 3 fallos".
            failures.pop(key, None)
            first_failure.pop(key, None)
        elif e.kind is EventKind.ACCEPTED:
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


def detect_ssh_scan(events: list[AuthEvent], cfg: Config) -> list[Finding]:
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        if e.kind is EventKind.PROBE:
            by_ip[e.ip].append(e)
    return [
        Finding(
            Severity.LOW,
            "ssh_scan",
            f"Escaneo del puerto de SSH desde {ip}",
            evs[0].timestamp,
            evs[-1].timestamp,
            len(evs),
            ip=ip,
            mitre="T1046 Network Service Discovery",
            details=(
                f"{len(evs)} conexiones que no llegaron a intentar entrar (sin saludo SSH o con cifrados "
                "antiguos): alguien está mirando qué versión de SSH tienes"
            ),
        )
        for ip, evs in by_ip.items()
        if len(evs) >= cfg.scan_min_probes
    ]


def _by_host_and_user(events: list[AuthEvent], kinds: set[EventKind]) -> dict[tuple[str, str], list[AuthEvent]]:
    grouped: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
    for e in events:
        if e.kind in kinds:
            grouped[(e.host, e.user)].append(e)
    return grouped


def detect_sudo_denied(events: list[AuthEvent], cfg: Config) -> list[Finding]:
    findings = []
    for (_, user), evs in _by_host_and_user(events, {EventKind.SUDO_DENIED}).items():
        last = evs[-1].extra or "(sin orden)"
        findings.append(
            Finding(
                Severity.MEDIUM,
                "sudo_denied",
                f"'{user}' intentó usar sudo sin tener permiso",
                evs[0].timestamp,
                evs[-1].timestamp,
                len(evs),
                user=user,
                mitre="T1548.003 Sudo and Sudo Caching",
                details=(
                    f"{len(evs)} intento(s); la última orden fue {last[:80]}. Si nadie lo esperaba, "
                    "puede ser una cuenta robada buscando cómo ser root"
                ),
            )
        )
    return findings


def detect_privilege_guessing(events: list[AuthEvent], cfg: Config) -> list[Finding]:
    findings = []
    for (_, user), evs in _by_host_and_user(events, {EventKind.SUDO_FAILED}).items():
        total = sum(e.count for e in evs)
        if total >= cfg.privilege_failures:
            findings.append(
                Finding(
                    Severity.MEDIUM,
                    "privilege_guessing",
                    f"'{user}' falló {total} veces la contraseña de sudo o su",
                    evs[0].timestamp,
                    evs[-1].timestamp,
                    total,
                    user=user,
                    mitre="T1548.003 Sudo and Sudo Caching",
                    details="alguien con una sesión abierta está probando contraseñas para hacerse root",
                )
            )
    return findings


def detect_account_created(events: list[AuthEvent], cfg: Config) -> list[Finding]:
    findings = []
    for e in events:
        if e.kind is not EventKind.ACCOUNT_CREATED:
            continue
        root_clone = e.extra == "UID=0"
        findings.append(
            Finding(
                Severity.CRITICAL if root_clone else Severity.MEDIUM,
                "account_created",
                f"Cuenta nueva '{e.user}'" + (" con UID 0 (otro root)" if root_clone else ""),
                e.timestamp,
                e.timestamp,
                1,
                user=e.user,
                mitre="T1136.001 Create Account",
                details=(
                    "una cuenta con UID 0 tiene todos los permisos de root: es una puerta trasera típica"
                    if root_clone
                    else "comprueba que la creó alguien de confianza: crear cuentas es una forma de quedarse dentro"
                ),
            )
        )
    return findings


# Grupos que dan root, directa o indirectamente (docker y lxd montan / dentro de un contenedor).
ADMIN_GROUPS = {"sudo", "wheel", "admin", "root", "docker", "lxd"}


def detect_admin_group(events: list[AuthEvent], cfg: Config) -> list[Finding]:
    seen: dict[tuple[str, str, str], AuthEvent] = {}
    for e in events:
        if e.kind is EventKind.GROUP_ADDED and e.extra in ADMIN_GROUPS:
            seen.setdefault((e.host, e.user, e.extra), e)
    return [
        Finding(
            Severity.HIGH,
            "admin_group",
            f"'{user}' añadido al grupo de administradores '{group}'",
            e.timestamp,
            e.timestamp,
            1,
            user=user,
            mitre="T1098 Account Manipulation",
            details=f"desde ahora '{user}' puede hacerse root; comprueba que era un cambio previsto",
        )
        for (_, user, group), e in seen.items()
    ]


DETECTORS = [
    detect_success_after_failures,
    detect_distributed_attack,
    detect_brute_force,
    detect_password_spraying,
    detect_root_login,
    detect_user_enumeration,
    detect_ssh_scan,
    detect_sudo_denied,
    detect_privilege_guessing,
    detect_account_created,
    detect_admin_group,
]


def analyze(events: list[AuthEvent], cfg: Config | None = None) -> Analysis:
    cfg = cfg or Config()
    events = sorted(events, key=lambda e: e.timestamp)
    result = Analysis(events)
    for detector in DETECTORS:
        result.findings.extend(detector(events, cfg))
    result.findings.sort(key=lambda f: (-f.severity, f.first_seen))
    return result

"""Parser de /var/log/auth.log (Debian/Ubuntu) o /var/log/secure (RHEL).

Saca los accesos de sshd y, además, lo que pasa dentro de la máquina y deja rastro en el
mismo log: sudo y su (quién intenta ser root), cuentas nuevas y gente que entra en
grupos de administrador (useradd, usermod, gpasswd), y los sondeos de escáneres que se
conectan al puerto de SSH sin llegar a intentar entrar.

Entiende los dos formatos de fecha habituales:

    Sep 25 10:15:32 servidor sshd[1234]: ...                    (syslog clásico)
    2026-09-25T10:15:32.123456+02:00 servidor sshd[1234]: ...   (Ubuntu 24.04, rsyslog moderno)

y los dos nombres del proceso de SSH, "sshd" y "sshd-session" (este último desde OpenSSH 9.8).
"""

from __future__ import annotations

import gzip
import re
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, tzinfo
from enum import Enum
from pathlib import Path

MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1)}

SYSLOG_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?P<proc>[\w.-]+)(?:\[\d+\])?: (?P<msg>.*)$"
)
ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) (?P<host>\S+) "
    r"(?P<proc>[\w.-]+)(?:\[\d+\])?: (?P<msg>.*)$"
)
SSH_PROCESSES = {"sshd", "sshd-session"}
IP = r"(?P<ip>[0-9a-fA-F.:]+)"

# El nombre de usuario lo elige quien se conecta y sshd lo escribe tal cual, con espacios y todo:
# con `ssh -l 'x from 10.0.0.1 port 22 ssh2' servidor` el log dice "...user x from 10.0.0.1 port 22
# ssh2 from <la IP de verdad> port ...". Por eso el usuario se lee con avaricia (.*) y la IP es
# siempre la ÚLTIMA de la línea, que es la que pone sshd. Si no, cualquiera podría meter la IP de
# otro en el informe y en la lista de bloqueo.
FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*) from (?P<ip>[0-9a-fA-F.:]+) port \d+"
    r"(?: ssh\d?)?(?:: .*)?$"
)
ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+) port \d+")
INVALID_USER = re.compile(r"^Invalid user (?P<user>.*) from (?P<ip>[0-9a-fA-F.:]+)(?: port \d+)?$")
# Un servidor que solo admite llaves no escribe "Failed password": el que prueba contraseñas se
# encuentra con que no se las piden y corta. Lo único que queda es esta línea.
PREAUTH = re.compile(
    r"^(?:Connection (?:closed|reset) by|Disconnected from) (?P<kind>authenticating|invalid) user (?P<user>.*) "
    r"(?P<ip>[0-9a-fA-F.:]+) port \d+(?: \[preauth\])?$"
)
# rsyslog con "$RepeatedMsgReduction on" (lo trae Ubuntu) junta los mensajes idénticos seguidos:
#   message repeated 4 times: [ Failed password for root from 203.0.113.5 port 22 ssh2]
REPEATED = re.compile(r"^message repeated (?P<n>\d{1,12}) times: \[ ?(?P<msg>.*?) ?\]$")
# Escáneres que se conectan al puerto 22 para ver qué hay, sin intentar entrar.
PROBES = [
    re.compile(rf"^Did not receive identification string from {IP}"),
    re.compile(rf"^banner exchange: Connection from {IP} port \d+: invalid format"),
    re.compile(rf"^Unable to negotiate with {IP} port \d+:"),
    re.compile(rf"^Protocol major versions differ for {IP}"),
    re.compile(rf"^Bad protocol version identification .* from {IP}"),
]

# sudo escribe "    pepe : TTY=pts/0 ; PWD=/home/pepe ; USER=root ; COMMAND=/usr/bin/apt update"
SUDO = re.compile(r"^\s*(?P<user>\S+) : (?P<rest>.*)$")
SUDO_FAILED = re.compile(r"^(?P<n>\d{1,6}) incorrect password attempts?")
SU_FAILED = [
    re.compile(r"^FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on"),  # su de util-linux
    re.compile(r"^FAILED su for (?P<target>\S+) by (?P<user>\S+)"),  # su de shadow (antiguo)
]
NEW_USER = re.compile(r"^new user: name=(?P<user>[^,\s]+), UID=(?P<uid>\d+)")
# "shadow group" es la misma operación escrita en /etc/gshadow: no se cuenta dos veces.
GROUP_ADDED = [
    re.compile(r"^add '(?P<user>[^']+)' to group '(?P<group>[^']+)'"),
    re.compile(r"^user (?P<user>\S+) added by \S+ to group (?P<group>\S+)"),
]
ACCOUNT_PROCESSES = {"useradd", "usermod", "gpasswd", "adduser"}

# Tope de repeticiones por línea: un log manipulado no debe poder llenar la memoria.
MAX_REPEAT = 10_000


class EventKind(str, Enum):
    FAILED = "failed"
    PREAUTH = "preauth"  # cortó antes de identificarse (lo normal contra un servidor de solo llaves)
    ACCEPTED = "accepted"
    INVALID_USER = "invalid_user"
    PROBE = "probe"  # alguien se conecta al puerto de SSH sin intentar entrar
    SUDO = "sudo"  # sudo permitido
    SUDO_DENIED = "sudo_denied"  # "user NOT in sudoers"
    SUDO_FAILED = "sudo_failed"  # contraseña mal en sudo o su
    ACCOUNT_CREATED = "account_created"
    GROUP_ADDED = "group_added"


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    host: str
    kind: EventKind
    user: str
    ip: str
    method: str | None = None
    invalid_user: bool = False
    extra: str = ""  # la orden de sudo, el grupo o el UID, según el tipo de evento
    count: int = 1  # sudo junta varios intentos fallidos en una sola línea


def _parse_iso_aware(ts: str) -> datetime:
    """La fecha ISO con su huso. Lanza ValueError si no se entiende."""
    ts = ts.replace("Z", "+00:00")
    # Python 3.10 no entiende "+0200" (sin los dos puntos) ni un número de decimales
    # distinto de 3 o 6, así que lo normalizo antes de llamar a fromisoformat.
    if re.search(r"[+-]\d{4}$", ts):
        ts = f"{ts[:-2]}:{ts[-2:]}"
    ts = re.sub(r"\.(\d+)", lambda m: "." + m.group(1)[:6].ljust(6, "0"), ts)
    return datetime.fromisoformat(ts)


def _parse_iso(ts: str, reference: tzinfo | None = None) -> datetime:
    # Me quedo con la hora local del servidor, igual que en el formato syslog. Si el log mezcla
    # husos (el cambio de hora de octubre, o un trozo en UTC), todo se pasa al de la primera
    # línea: si no, 02:01+01:00 quedaría antes que 02:59+02:00 y el orden real se perdería.
    moment = _parse_iso_aware(ts)
    if reference is not None and moment.tzinfo is not None:
        moment = moment.astimezone(reference)
    return moment.replace(tzinfo=None)


def _date(year: int, month: int, day: int, hms: str) -> datetime | None:
    hh, mm, ss = (int(x) for x in hms.split(":"))
    try:
        return datetime(year, month, day, hh, mm, ss)
    except ValueError:
        return None  # 30 de febrero y cosas así: línea corrupta


def _sudo_command(rest: str) -> str:
    _, found, command = rest.partition(" ; COMMAND=")
    return command if found else ""


def _parse_sudo(timestamp: datetime, host: str, msg: str) -> AuthEvent | None:
    m = SUDO.match(msg)
    if not m:
        return None
    user, rest = m["user"], m["rest"]
    if rest.startswith(("user NOT in sudoers", "command not allowed", "user NOT authorized on host")):
        return AuthEvent(timestamp, host, EventKind.SUDO_DENIED, user, "", extra=_sudo_command(rest))
    if f := SUDO_FAILED.match(rest):
        return AuthEvent(timestamp, host, EventKind.SUDO_FAILED, user, "", extra=_sudo_command(rest), count=int(f["n"]))
    if rest.startswith("TTY=") or rest.startswith("PWD="):
        return AuthEvent(timestamp, host, EventKind.SUDO, user, "", extra=_sudo_command(rest))
    return None


def parse_system_message(timestamp: datetime, host: str, process: str, msg: str) -> AuthEvent | None:
    """sudo, su y cambios de cuentas: lo que no es sshd pero también va a auth.log."""
    if process == "sudo":
        return _parse_sudo(timestamp, host, msg)
    if process == "su":
        for regex in SU_FAILED:
            if m := regex.match(msg):
                return AuthEvent(timestamp, host, EventKind.SUDO_FAILED, m["user"], "", extra=m["target"])
        return None
    if process in ACCOUNT_PROCESSES:
        if m := NEW_USER.match(msg):
            return AuthEvent(timestamp, host, EventKind.ACCOUNT_CREATED, m["user"], "", extra=f"UID={m['uid']}")
        for regex in GROUP_ADDED:
            if m := regex.match(msg):
                return AuthEvent(timestamp, host, EventKind.GROUP_ADDED, m["user"], "", extra=m["group"])
    return None


def parse_message(timestamp: datetime, host: str, msg: str) -> AuthEvent | None:
    """Una línea de sshd."""
    if m := FAILED.match(msg):
        return AuthEvent(
            timestamp, host, EventKind.FAILED, m["user"], m["ip"], m["method"], invalid_user=bool(m["invalid"])
        )
    if m := ACCEPTED.match(msg):
        return AuthEvent(timestamp, host, EventKind.ACCEPTED, m["user"], m["ip"], m["method"])
    if m := INVALID_USER.match(msg):
        return AuthEvent(timestamp, host, EventKind.INVALID_USER, m["user"], m["ip"], invalid_user=True)
    if m := PREAUTH.match(msg):
        return AuthEvent(
            timestamp, host, EventKind.PREAUTH, m["user"], m["ip"], "preauth", invalid_user=m["kind"] == "invalid"
        )
    for regex in PROBES:
        if m := regex.match(msg):
            return AuthEvent(timestamp, host, EventKind.PROBE, "", m["ip"])
    return None


def parse_lines(lines: Iterable[str], year: int | None = None, now: datetime | None = None) -> Iterator[AuthEvent]:
    """Convierte líneas en eventos. Lo que no sea sshd, sudo, su o cambios de cuentas se ignora.

    El formato syslog clásico no guarda el año:
    - con `year`, se empieza en ese año y se suma uno cada vez que el mes va hacia
      atrás (un log que pasa de diciembre a enero).
    - sin `year`, se deduce de la fecha actual: si la fecha quedaría en el futuro, la
      línea es del año pasado. Así un "Dec 31" leído el 1 de enero no acaba fechado
      dentro de doce meses.
    """
    now = now or datetime.now()
    previous_month = None
    reference: tzinfo | None = None  # el huso de la primera línea ISO
    for line in lines:
        line = line.rstrip("\r\n")
        if m := SYSLOG_LINE.match(line):
            month = MONTHS.get(m["mon"])
            if month is None:
                continue
            day = int(m["day"])
            if year is not None:
                if previous_month is not None and month < previous_month:
                    year += 1
                previous_month = month
                timestamp = _date(year, month, day, m["time"])
            else:
                timestamp = _date(now.year, month, day, m["time"])
                if timestamp is None or timestamp > now + timedelta(days=1):
                    timestamp = _date(now.year - 1, month, day, m["time"])
            if timestamp is None:
                continue
        elif m := ISO_LINE.match(line):
            try:
                timestamp = _parse_iso(m["ts"], reference)
                if reference is None:
                    reference = _parse_iso_aware(m["ts"]).tzinfo
            except ValueError:
                continue
        else:
            continue
        msg, times = m["msg"], 1
        if r := REPEATED.match(msg):
            msg, times = r["msg"], min(int(r["n"]), MAX_REPEAT)
        process = m["proc"]
        if process in SSH_PROCESSES:
            event = parse_message(timestamp, m["host"], msg)
        else:
            event = parse_system_message(timestamp, m["host"], process, msg)
        if event is not None:
            for _ in range(times):
                yield event


def read_lines(path: Path | str) -> Iterator[str]:
    """Lee un log normal, uno rotado y comprimido (.gz) o la entrada estándar ("-")."""
    if str(path) == "-":
        yield from sys.stdin
        return
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        yield from fh

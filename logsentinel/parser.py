"""Parser de las líneas de sshd de /var/log/auth.log (Debian/Ubuntu) o /var/log/secure (RHEL).

Entiende los dos formatos de fecha habituales:

    Sep 25 10:15:32 servidor sshd[1234]: ...                    (syslog clásico)
    2026-09-25T10:15:32.123456+02:00 servidor sshd[1234]: ...   (Ubuntu 24.04, rsyslog moderno)

y los dos nombres del proceso, "sshd" y "sshd-session" (este último desde OpenSSH 9.8).
"""

from __future__ import annotations

import gzip
import re
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1)}

SYSLOG_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"sshd(?:-session)?\[\d+\]: (?P<msg>.*)$"
)
ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) (?P<host>\S+) "
    r"sshd(?:-session)?\[\d+\]: (?P<msg>.*)$"
)

FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>[0-9a-fA-F.:]+) port \d+"
)
ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+) port \d+")
INVALID_USER = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F.:]+)")
# rsyslog con "$RepeatedMsgReduction on" (lo trae Ubuntu) junta los mensajes idénticos seguidos:
#   message repeated 4 times: [ Failed password for root from 203.0.113.5 port 22 ssh2]
REPEATED = re.compile(r"^message repeated (?P<n>\d{1,12}) times: \[ ?(?P<msg>.*?) ?\]$")
# Tope de repeticiones por línea: un log manipulado no debe poder llenar la memoria.
MAX_REPEAT = 10_000


class EventKind(str, Enum):
    FAILED = "failed"
    ACCEPTED = "accepted"
    INVALID_USER = "invalid_user"


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    host: str
    kind: EventKind
    user: str
    ip: str
    method: str | None = None
    invalid_user: bool = False


def _parse_iso(ts: str) -> datetime:
    ts = ts.replace("Z", "+00:00")
    # Python 3.10 no entiende "+0200" (sin los dos puntos) ni un número de decimales
    # distinto de 3 o 6, así que lo normalizo antes de llamar a fromisoformat.
    if re.search(r"[+-]\d{4}$", ts):
        ts = f"{ts[:-2]}:{ts[-2:]}"
    ts = re.sub(r"\.(\d+)", lambda m: "." + m.group(1)[:6].ljust(6, "0"), ts)
    # Me quedo con la hora local del servidor, igual que en el formato syslog.
    return datetime.fromisoformat(ts).replace(tzinfo=None)


def _date(year: int, month: int, day: int, hms: str) -> datetime | None:
    hh, mm, ss = (int(x) for x in hms.split(":"))
    try:
        return datetime(year, month, day, hh, mm, ss)
    except ValueError:
        return None  # 30 de febrero y cosas así: línea corrupta


def parse_message(timestamp: datetime, host: str, msg: str) -> AuthEvent | None:
    if m := FAILED.match(msg):
        return AuthEvent(
            timestamp, host, EventKind.FAILED, m["user"], m["ip"], m["method"], invalid_user=bool(m["invalid"])
        )
    if m := ACCEPTED.match(msg):
        return AuthEvent(timestamp, host, EventKind.ACCEPTED, m["user"], m["ip"], m["method"])
    if m := INVALID_USER.match(msg):
        return AuthEvent(timestamp, host, EventKind.INVALID_USER, m["user"], m["ip"], invalid_user=True)
    return None


def parse_lines(lines: Iterable[str], year: int | None = None, now: datetime | None = None) -> Iterator[AuthEvent]:
    """Convierte líneas en eventos. Lo que no sea autenticación de sshd se ignora.

    El formato syslog clásico no guarda el año:
    - con `year`, se empieza en ese año y se suma uno cada vez que el mes va hacia
      atrás (un log que pasa de diciembre a enero).
    - sin `year`, se deduce de la fecha actual: si la fecha quedaría en el futuro, la
      línea es del año pasado. Así un "Dec 31" leído el 1 de enero no acaba fechado
      dentro de doce meses.
    """
    now = now or datetime.now()
    previous_month = None
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
                timestamp = _parse_iso(m["ts"])
            except ValueError:
                continue
        else:
            continue
        msg, times = m["msg"], 1
        if r := REPEATED.match(msg):
            msg, times = r["msg"], min(int(r["n"]), MAX_REPEAT)
        event = parse_message(timestamp, m["host"], msg)
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

"""Genera samples/auth.log, un auth.log inventado con tráfico normal y varios ataques.

Las IPs son de los rangos reservados para documentación (RFC 5737: 192.0.2.0/24,
198.51.100.0/24 y 203.0.113.0/24), no son de nadie.
Uso: python samples/generate_sample.py
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

HOST = "srv-web01"
OUT = Path(__file__).with_name("auth.log")


class LogWriter:
    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)
        self.lines: list[tuple[datetime, str]] = []

    def sshd(self, when: datetime, msg: str) -> None:
        pid = self.rng.randint(1000, 65000)
        self.lines.append((when, f"{HOST} sshd[{pid}]: {msg}"))

    def other(self, when: datetime, msg: str) -> None:
        self.lines.append((when, f"{HOST} {msg}"))

    def port(self) -> int:
        return self.rng.randint(32768, 60999)

    def failed(self, when: datetime, user: str, ip: str, invalid: bool = False) -> None:
        if invalid:
            self.sshd(when, f"Invalid user {user} from {ip} port {self.port()}")
        prefix = "invalid user " if invalid else ""
        self.sshd(when, f"Failed password for {prefix}{user} from {ip} port {self.port()} ssh2")

    def accepted(self, when: datetime, user: str, ip: str, method: str = "publickey") -> None:
        suffix = ": ED25519 SHA256:" + "".join(self.rng.choices("abcdefghijkLMNOPQ0123456789", k=43))
        extra = suffix if method == "publickey" else ""
        self.sshd(when, f"Accepted {method} for {user} from {ip} port {self.port()} ssh2{extra}")
        self.sshd(when, f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)")

    def write(self, path: Path) -> None:
        self.lines.sort(key=lambda item: item[0])
        text = "".join(f"{when:%b} {when.day:>2} {when:%H:%M:%S} {line}\n" for when, line in self.lines)
        path.write_text(text, encoding="utf-8")


def main() -> None:
    log = LogWriter()
    rng = log.rng
    t0 = datetime(2026, 9, 25, 6, 0, 0)

    # Tráfico normal: el equipo entra con clave pública durante el día.
    for day_minute in range(0, 14 * 60, 47):
        user, ip = rng.choice([("alice", "198.51.100.10"), ("bob", "198.51.100.11"), ("deploy", "198.51.100.12")])
        log.accepted(t0 + timedelta(minutes=day_minute), user, ip)
    # Alguien se equivoca de contraseña una vez: no debe generar alertas.
    log.failed(t0 + timedelta(hours=3, minutes=2), "bob", "198.51.100.11")
    log.accepted(t0 + timedelta(hours=3, minutes=3), "bob", "198.51.100.11", "password")

    # 1) Fuerza bruta clásica contra root: 40 intentos en unos 3 minutos.
    t = t0 + timedelta(hours=1, minutes=15)
    for _ in range(40):
        t += timedelta(seconds=rng.randint(2, 6))
        log.failed(t, "root", "203.0.113.45")

    # 2) Password spraying: muchas cuentas, un intento o dos cada una.
    t = t0 + timedelta(hours=2)
    users = ["admin", "alice", "bob", "carol", "dave", "deploy", "ftp", "git", "jenkins", "mysql", "oracle", "www"]
    for user in users:
        for _ in range(rng.choice([1, 1, 2])):
            t += timedelta(seconds=rng.randint(20, 90))
            log.failed(t, user, "203.0.113.77", invalid=user in {"carol", "dave", "ftp", "jenkins", "oracle", "www"})

    # 3) Enumeración de usuarios que no existen.
    t = t0 + timedelta(hours=4, minutes=30)
    for user in ["test", "ubuntu", "pi", "postgres", "hadoop", "minecraft", "steam", "user1"]:
        t += timedelta(seconds=rng.randint(5, 40))
        log.failed(t, user, "192.0.2.200", invalid=True)

    # 4) Ataque distribuido (botnet) contra "admin": pocas peticiones por IP para no llamar la atención.
    t = t0 + timedelta(hours=6)
    for host in range(10, 17):
        for _ in range(2):
            t += timedelta(minutes=rng.randint(1, 9))
            log.failed(t, "admin", f"192.0.2.{host}")

    # 5) El peor caso: fallos y después un acceso correcto desde la misma IP.
    t = t0 + timedelta(hours=9, minutes=41)
    for _ in range(8):
        t += timedelta(seconds=rng.randint(3, 15))
        log.failed(t, "backup", "203.0.113.99")
    log.accepted(t + timedelta(seconds=7), "backup", "203.0.113.99", "password")

    # 6) Ya dentro, el intruso intenta hacerse root: sudo sin permiso y luego su.
    t += timedelta(minutes=2)
    log.other(t, "sudo:   backup : user NOT in sudoers ; TTY=pts/3 ; PWD=/var/backups ; USER=root ; COMMAND=/bin/bash")
    for _ in range(3):
        t += timedelta(seconds=rng.randint(4, 12))
        log.other(t, f"su[{rng.randint(1000, 65000)}]: FAILED SU (to root) backup on pts/3")

    # 7) Un escáner mira qué SSH hay en el puerto 22 sin intentar entrar.
    t = t0 + timedelta(hours=7, minutes=20)
    for _ in range(6):
        t += timedelta(seconds=rng.randint(1, 4))
        log.sshd(t, f"Did not receive identification string from 192.0.2.50 port {log.port()}")

    # 8) Alguien deja una puerta trasera: una cuenta con UID 0 y otra en el grupo sudo.
    t = t0 + timedelta(hours=12, minutes=30)
    log.other(t, "useradd[31337]: new user: name=sysupdate, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/2")
    log.other(t + timedelta(seconds=20), "usermod[31338]: add 'deploy' to group 'sudo'")
    log.other(t + timedelta(seconds=20), "usermod[31338]: add 'deploy' to shadow group 'sudo'")

    # Uso normal de sudo: no debe generar alertas.
    apt = "sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"
    log.other(t0 + timedelta(hours=5), apt)

    # 9) Un administrador entra directamente como root (mala práctica, no un ataque).
    log.accepted(t0 + timedelta(hours=11, minutes=5), "root", "198.51.100.20")

    # Ruido habitual que el parser debe ignorar.
    for minute in range(0, 14 * 60, 60):
        when = t0 + timedelta(minutes=minute)
        log.other(when, "CRON[4242]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
        log.sshd(when + timedelta(seconds=30), f"Connection closed by 203.0.113.45 port {log.port()} [preauth]")

    log.write(OUT)
    print(f"{OUT} generado con {len(log.lines)} líneas")


if __name__ == "__main__":
    main()

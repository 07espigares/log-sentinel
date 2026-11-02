"""Línea de comandos.

Dos modos:
  - por defecto analiza uno o varios ficheros y saca un informe
  - con --follow vigila un fichero como `tail -F` y avisa de cada hallazgo nuevo

Y dos tipos de log: SSH (auth.log / secure) o, con --web, nginx / Apache.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from .ansi import clean, paint
from .dashboard import dashboard_from
from .detectors import Config, Finding, Severity, analyze
from .follow import Tailer
from .live import LiveEngine
from .notifier import NotifyError, build_notifier
from .parser import parse_lines, read_lines
from .report import INDENT, severity_tag, to_json, to_markdown, to_text, web_to_json, web_to_markdown, web_to_text
from .webserver import analyze_web, parse_web_lines

SEVERITIES = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL}


class Mode:
    """Lo que cambia entre analizar logs de SSH y logs web."""

    def __init__(self, web: bool) -> None:
        self.kind = "web" if web else "ssh"
        self.parse = parse_web_lines if web else parse_lines
        self.analyze = analyze_web if web else analyze
        if web:
            self.renderers = {"text": web_to_text, "md": web_to_markdown, "json": web_to_json}
        else:
            self.renderers = {"text": to_text, "md": to_markdown, "json": to_json}


def positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value <= 0:
        raise argparse.ArgumentTypeError(f"tiene que ser un número entero mayor que 0: {text!r}")
    return value


def when(text: str) -> datetime:
    """Fecha de --since/--until: AAAA-MM-DD o AAAA-MM-DD HH:MM[:SS]."""
    try:
        moment = datetime.fromisoformat(text.strip().replace("T", " "))
    except ValueError:
        raise argparse.ArgumentTypeError(f"fecha no válida {text!r}: usa AAAA-MM-DD o AAAA-MM-DD HH:MM") from None
    # Como el parser con las fechas ISO: la hora tal como está escrita, sin zona.
    return moment.replace(tzinfo=None)


def when_end(text: str) -> datetime:
    """Como when(), pero un día sin hora incluye el día entero: --until 2026-09-25."""
    moment = when(text)
    if len(text.strip()) == 10:
        moment += timedelta(days=1, microseconds=-1)
    return moment


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logsentinel",
        description="Detecta ataques en logs de SSH (auth.log) y de servidores web (nginx/Apache)",
    )
    p.add_argument("logs", nargs="+", help="ficheros de log (vale .gz, y '-' para leer de stdin)")
    p.add_argument("--web", action="store_true", help="los ficheros son logs de nginx/Apache")
    p.add_argument("--follow", "-f", action="store_true", help="vigilar el fichero en vivo y avisar al momento")
    p.add_argument("--from-start", action="store_true", help="con --follow, procesar también lo que ya está escrito")
    p.add_argument(
        "--notify",
        action="append",
        default=[],
        choices=["telegram", "discord", "webhook"],
        help="mandar avisos por este canal (se puede repetir). Credenciales en variables de entorno",
    )
    p.add_argument(
        "--min-severity",
        choices=list(SEVERITIES),
        default="high",
        help="prioridad mínima para mandar un aviso (por defecto high)",
    )
    p.add_argument("--dashboard", type=Path, metavar="HTML", help="guardar un panel HTML en esta ruta")
    p.add_argument("--format", choices=["text", "md", "json"], default="text", help="formato del informe")
    p.add_argument(
        "--year",
        type=int,
        help="año de las líneas syslog, que no lo guardan (por defecto se deduce de la fecha actual)",
    )
    p.add_argument(
        "--threshold", type=positive_int, default=10, help="fallos desde una IP para considerarlo fuerza bruta"
    )
    p.add_argument("--window", type=positive_int, default=300, help="ventana de la fuerza bruta, en segundos")
    p.add_argument("--since", type=when, metavar="FECHA", help="analizar solo desde esta fecha (AAAA-MM-DD [HH:MM])")
    p.add_argument("--until", type=when_end, metavar="FECHA", help="analizar solo hasta esta fecha (incluida)")
    p.add_argument("--blocklist", type=Path, help="escribir aquí las IPs atacantes, una por línea")
    p.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="CIDR",
        help="red que nunca va a la lista de bloqueo (se puede repetir), p. ej. 10.0.0.0/8",
    )
    p.add_argument("--host", default="", help="nombre de la máquina, para ponerlo en los avisos")
    return p


def filter_allowed(ips, allowed):
    kept = []
    for ip in ips:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not any(address in net for net in allowed):
            kept.append(ip)
    return kept


def _build_notifiers(kinds):
    notifiers = []
    for kind in dict.fromkeys(kinds):  # quita repetidos sin cambiar el orden
        try:
            notifiers.append(build_notifier(kind))
        except NotifyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return None
    return notifiers


def _emit(finding: Finding, notifiers, min_sev: Severity, host: str, out) -> None:
    stamp = paint(f"{finding.last_seen:%H:%M:%S}", "gray")
    print(f"{stamp} {severity_tag(finding.severity)}{paint(clean(finding.title), 'bold')}", file=out)
    print(paint(f"{' ' * 9}{INDENT}{clean(finding.details)}", "gray"), file=out)
    if finding.severity < min_sev:
        return
    for notifier in notifiers:
        try:
            notifier.send(finding, host)
        except NotifyError as exc:
            # Si Telegram está caído no quiero que se pare la vigilancia: se avisa y se sigue.
            print(paint(f"{' ' * 9}{INDENT}(no se pudo avisar por {notifier.name}: {exc})", "yellow"), file=out)


def run_follow(path, mode, cfg, notifiers, min_sev, host, out, from_start=False, poll=1.0, stop=None, sleep=time.sleep):
    if str(path) == "-" or str(path).endswith(".gz") or Path(path).is_dir():
        print("error: --follow necesita un fichero normal (ni stdin, ni .gz, ni un directorio)", file=sys.stderr)
        return 2
    channels = ", ".join(n.name for n in notifiers) or "solo en pantalla"
    print(paint(f"log-sentinel vigilando {path} ({mode.kind}), avisos: {channels}", "bold", "cyan"), file=out)
    print(paint(f"Avisa a partir de prioridad {min_sev.label}. Ctrl-C para salir.\n", "gray"), file=out)

    tailer = Tailer(path, from_start=from_start)
    engine = LiveEngine(mode.parse, mode.analyze, cfg, lambda f: _emit(f, notifiers, min_sev, host, out))
    try:
        while stop is None or not stop():
            lines = tailer.read_new()
            if lines:
                engine.feed(lines)
            else:
                sleep(poll)
    except KeyboardInterrupt:
        print(paint("\nlog-sentinel parado.", "gray"), file=out)
    finally:
        tailer.close()
    return 0


def _counted(lines, counter: list[int]):
    for line in lines:
        counter[0] += 1
        yield line


def _in_range(events, since, until):
    return [e for e in events if (since is None or e.timestamp >= since) and (until is None or e.timestamp <= until)]


def run_batch(args, mode, cfg, allowed) -> int:
    events = []
    for log in args.logs:
        lines = [0]
        try:
            parsed = list(mode.parse(_counted(read_lines(log), lines), args.year))
        except OSError as exc:
            print(f"error: no se pudo leer {log}: {exc.strerror or exc}", file=sys.stderr)
            return 2
        if lines[0] and not parsed:
            # Si no, un log equivocado sale como «Sin hallazgos» y parece que todo va bien.
            hint = "si es auth.log, quita --web" if mode.kind == "web" else "si es de nginx o Apache, usa --web"
            print(f"aviso: ninguna de las {lines[0]} líneas de {log} se ha entendido ({hint})", file=sys.stderr)
        events.extend(parsed)
    events = _in_range(events, getattr(args, "since", None), getattr(args, "until", None))

    analysis = mode.analyze(events, cfg)
    source = ", ".join(args.logs)
    print(mode.renderers[args.format](analysis, source))

    try:
        if args.dashboard:
            args.dashboard.write_text(dashboard_from(analysis, source, mode.kind), encoding="utf-8")
            print(f"panel guardado en {args.dashboard}", file=sys.stderr)
        if args.blocklist:
            ips = filter_allowed(analysis.offending_ips(), allowed)
            args.blocklist.write_text("".join(f"{ip}\n" for ip in ips), encoding="utf-8")
            print(f"{len(ips)} IP(s) guardadas en {args.blocklist}", file=sys.stderr)
    except OSError as exc:
        print(f"error: no se pudo escribir {exc.filename}: {exc.strerror}", file=sys.stderr)
        return 2

    # Código 1 si hay algo alto o crítico: así se puede usar desde cron con `|| avisar`.
    return 1 if any(f.severity >= Severity.HIGH for f in analysis.findings) else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        allowed = [ipaddress.ip_network(cidr, strict=False) for cidr in args.allow]
    except ValueError as exc:
        print(f"error: red no válida en --allow: {exc}", file=sys.stderr)
        return 2

    mode = Mode(args.web)
    cfg = Config(brute_force_threshold=args.threshold, window=timedelta(seconds=args.window))

    if args.follow:
        if len(args.logs) != 1:
            print("error: --follow solo vigila un fichero", file=sys.stderr)
            return 2
        notifiers = _build_notifiers(args.notify)
        if notifiers is None:
            return 2
        min_sev = SEVERITIES[args.min_severity]
        return run_follow(args.logs[0], mode, cfg, notifiers, min_sev, args.host, sys.stdout, args.from_start)

    if args.notify:
        print("aviso: --notify solo se usa junto con --follow", file=sys.stderr)
    return run_batch(args, mode, cfg, allowed)


if __name__ == "__main__":
    sys.exit(main())

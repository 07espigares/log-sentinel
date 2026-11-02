"""Detección en vivo: guarda los eventos recientes y avisa de cada hallazgo una sola vez.

No hay detectores especiales para el modo en vivo. Cada vez que llegan líneas nuevas se
añaden a una lista, se tiran las más viejas que `horizon` y se vuelve a pasar el
análisis normal por encima. Un hallazgo se avisa la primera vez que aparece; si el
ataque para y sus eventos salen de la ventana, cuando vuelva se avisará otra vez.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from .detectors import Config, Finding


def _key(f: Finding) -> tuple:
    # En la fuerza bruta el "usuario" del hallazgo cambia si el atacante prueba otra
    # cuenta a mitad del ataque, pero sigue siendo el mismo ataque: no cuenta para la clave.
    if f.rule == "brute_force":
        return (f.rule, f.ip)
    return (f.rule, f.ip, f.user)


@dataclass
class LiveEngine:
    parse: Callable[[Iterable[str]], Iterable[Any]]  # parse_lines o parse_web_lines
    analyze: Callable[[list[Any], Config], Any]  # analyze o analyze_web
    cfg: Config
    on_finding: Callable[[Finding], None]
    horizon: timedelta = timedelta(hours=2)
    max_events: int = 50_000  # por si acaso: un ataque muy grande no se come toda la RAM
    events: list = field(default_factory=list)
    _active: dict = field(default_factory=dict)  # clave del hallazgo -> último evento visto

    def feed(self, lines: Iterable[str]) -> list[Finding]:
        """Procesa líneas nuevas. Devuelve los hallazgos nuevos (y llama a on_finding con cada uno)."""
        new_events = list(self.parse(lines))
        if not new_events:
            return []
        self.events.extend(new_events)
        cutoff = self._prune()
        # Un ataque cuyos eventos ya han caducado está terminado, aunque no haya llegado
        # ninguna línea entre medias que lo haya hecho desaparecer del análisis.
        self._active = {k: last for k, last in self._active.items() if last >= cutoff}

        current = {_key(f): f for f in self.analyze(self.events, self.cfg).findings}
        fresh = [f for k, f in current.items() if k not in self._active]
        self._active = {k: f.last_seen for k, f in current.items()}
        fresh.sort(key=lambda f: (-f.severity, f.first_seen))
        for finding in fresh:
            self.on_finding(finding)
        return fresh

    def _prune(self):
        cutoff = max(e.timestamp for e in self.events) - self.horizon
        self.events = [e for e in self.events if e.timestamp >= cutoff]
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events :]
        return cutoff

"""
alert_store.py — In-memory alert store with SSE pub/sub support.

Phase 2: Stores Alert objects in a plain dict keyed by alert.id.
No external broker or database required — suitable for demonstration purposes.

SSE subscribers register via subscribe() and receive new alerts through
asyncio.Queue instances. The store is a module-level singleton accessed via
`get_alert_store()`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.models.alert import Alert

logger = logging.getLogger(__name__)


class AlertStore:
    """
    Thread-safe (within asyncio event loop) in-memory alert store.

    Keyed by alert.id (str). Newest alerts sort first via _insertion_order list.
    SSE subscribers get a dedicated asyncio.Queue; add_alert() broadcasts to all.
    """

    def __init__(self) -> None:
        self._alerts: dict[str, Alert] = {}
        # Maintain insertion order separately so list_alerts can sort correctly.
        self._insertion_order: list[str] = []
        # SSE pub/sub: each connected stream consumer gets its own queue.
        self._subscribers: list[asyncio.Queue[Alert]] = []

    # ------------------------------------------------------------------ #
    # CRUD                                                                 #
    # ------------------------------------------------------------------ #

    def add_alert(self, alert: Alert) -> Alert:
        """
        Store an alert and broadcast it to all SSE subscribers.

        If an alert with the same id already exists it is overwritten.
        """
        if alert.id not in self._alerts:
            self._insertion_order.append(alert.id)
        self._alerts[alert.id] = alert
        logger.info(
            "AlertStore.add_alert id=%s severity=%s signature=%s",
            alert.id,
            alert.severity,
            alert.signature[:60],
        )
        self._broadcast(alert)
        return alert

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Return the Alert for the given id, or None if not found."""
        return self._alerts.get(alert_id)

    def list_alerts(
        self, limit: int = 50, severity: Optional[int] = None
    ) -> list[Alert]:
        """
        Return up to `limit` alerts, most recent first.

        Args:
            limit:    Maximum number of alerts to return (default 50).
            severity: If given, filter to alerts whose severity == this value.
        """
        # Reverse insertion order → newest first
        ordered_ids = list(reversed(self._insertion_order))
        alerts = [self._alerts[aid] for aid in ordered_ids if aid in self._alerts]
        if severity is not None:
            alerts = [a for a in alerts if a.severity == severity]
        return alerts[:limit]

    def clear_all(self) -> None:
        """Remove all alerts from the store (does not notify subscribers)."""
        self._alerts.clear()
        self._insertion_order.clear()
        logger.info("AlertStore cleared.")

    # ------------------------------------------------------------------ #
    # SSE pub/sub                                                          #
    # ------------------------------------------------------------------ #

    def subscribe(self) -> asyncio.Queue[Alert]:
        """
        Register a new SSE consumer.

        Returns a queue that will receive Alert objects whenever add_alert()
        is called. Callers must call unsubscribe() when the connection closes.
        """
        q: asyncio.Queue[Alert] = asyncio.Queue()
        self._subscribers.append(q)
        logger.debug("SSE subscriber added — total=%d", len(self._subscribers))
        return q

    def unsubscribe(self, q: asyncio.Queue[Alert]) -> None:
        """Remove a previously registered SSE consumer queue."""
        try:
            self._subscribers.remove(q)
            logger.debug(
                "SSE subscriber removed — total=%d", len(self._subscribers)
            )
        except ValueError:
            pass

    def _broadcast(self, alert: Alert) -> None:
        """Put a newly ingested alert onto every subscriber queue."""
        dead: list[asyncio.Queue[Alert]] = []
        for q in self._subscribers:
            try:
                q.put_nowait(alert)
            except asyncio.QueueFull:
                # Slow consumer — drop and remove to avoid backlog
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)

    # ------------------------------------------------------------------ #
    # Properties                                                           #
    # ------------------------------------------------------------------ #

    @property
    def count(self) -> int:
        """Total number of stored alerts."""
        return len(self._alerts)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_store_instance: Optional[AlertStore] = None


def get_alert_store() -> AlertStore:
    """Return the module-level AlertStore singleton, creating it if needed."""
    global _store_instance
    if _store_instance is None:
        _store_instance = AlertStore()
    return _store_instance

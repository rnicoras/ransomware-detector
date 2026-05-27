from __future__ import annotations
import asyncio
import logging
from typing import AsyncIterator, Tuple, Type

log = logging.getLogger(__name__)

AnyEvent = object

class EventBus:
    def __init__(self, maxsize: int = 1024) -> None:
        self._subscribers: list[Tuple[Tuple[type, ...], asyncio.Queue]] = []
        self._maxsize = maxsize
        self._published = 0
        self._dropped = 0

    async def publish(self, event: AnyEvent) -> None:
        self._published += 1
        for watched_types, queue in self._subscribers:
            if isinstance(event, watched_types):
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    self._dropped += 1
                    log.warning(
                        "Event bus queue full — dropping %s (total dropped: %d)",
                        type(event).__name__,
                        self._dropped,
                    )

    def subscribe(self, *event_types: Type) -> "_Subscription":
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._maxsize)
        entry = (tuple(event_types), queue)
        self._subscribers.append(entry)
        return _Subscription(queue, entry, self._subscribers)

    @property
    def stats(self) -> dict:
        return {
            "published": self._published,
            "dropped": self._dropped,
            "subscribers": len(self._subscribers),
        }


class _Subscription:
    def __init__(self, queue, entry, all_subscribers) -> None:
        self._queue = queue
        self._entry = entry
        self._all_subscribers = all_subscribers
        self._active = True

    def __aiter__(self) -> AsyncIterator:
        return self

    async def __anext__(self) -> AnyEvent:
        if not self._active:
            raise StopAsyncIteration
        return await self._queue.get()

    async def __aenter__(self) -> "_Subscription":
        return self

    async def __aexit__(self, *_) -> None:
        self.cancel()

    def cancel(self) -> None:
        self._active = False
        try:
            self._all_subscribers.remove(self._entry)
        except ValueError:
            pass
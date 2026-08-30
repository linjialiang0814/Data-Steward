"""Bounded in-memory WebSocket subscriptions.

SQLite remains the durable source of truth. These queues only wake connected
clients so they can read committed events in sequence order.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from .models import ConversationEvent


@dataclass(eq=False, slots=True)
class Subscription:
    conversation_id: str
    queue: asyncio.Queue[ConversationEvent]
    overflowed: asyncio.Event = field(default_factory=asyncio.Event)


class SubscriptionManager:
    def __init__(self, *, queue_size: int = 128) -> None:
        if queue_size < 1:
            raise ValueError("queue_size must be positive")
        self._queue_size = queue_size
        self._subscriptions: dict[str, set[Subscription]] = {}
        self._lock = asyncio.Lock()
        self._published_count = 0

    @property
    def subscriber_count(self) -> int:
        return sum(len(items) for items in self._subscriptions.values())

    @property
    def published_count(self) -> int:
        return self._published_count

    @property
    def queued_event_count(self) -> int:
        return sum(
            subscription.queue.qsize()
            for items in self._subscriptions.values()
            for subscription in items
        )

    async def register(self, conversation_id: str) -> Subscription:
        subscription = Subscription(
            conversation_id=conversation_id,
            queue=asyncio.Queue(maxsize=self._queue_size),
        )
        async with self._lock:
            self._subscriptions.setdefault(conversation_id, set()).add(
                subscription
            )
        return subscription

    async def unregister(self, subscription: Subscription) -> None:
        async with self._lock:
            items = self._subscriptions.get(subscription.conversation_id)
            if items is None:
                return
            items.discard(subscription)
            if not items:
                self._subscriptions.pop(subscription.conversation_id, None)

    async def publish(self, event: ConversationEvent) -> None:
        async with self._lock:
            self._published_count += 1
            items = tuple(
                self._subscriptions.get(event.conversation_id, ())
            )
            for subscription in items:
                try:
                    subscription.queue.put_nowait(event)
                except asyncio.QueueFull:
                    subscription.overflowed.set()
                    self._subscriptions[event.conversation_id].discard(
                        subscription
                    )
            remaining = self._subscriptions.get(event.conversation_id)
            if remaining is not None and not remaining:
                self._subscriptions.pop(event.conversation_id, None)

    async def next_event(
        self,
        subscription: Subscription,
    ) -> ConversationEvent:
        queue_task = asyncio.create_task(subscription.queue.get())
        overflow_task = asyncio.create_task(subscription.overflowed.wait())
        try:
            done, _ = await asyncio.wait(
                {queue_task, overflow_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if overflow_task in done and subscription.overflowed.is_set():
                raise SubscriptionOverflowError
            return queue_task.result()
        finally:
            await cancel_and_drain_tasks(queue_task, overflow_task)


async def cancel_and_drain_tasks(*tasks: asyncio.Task[Any]) -> None:
    """Cancel and await only tasks explicitly owned by the caller."""
    for task in tasks:
        if not task.done():
            task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


class SubscriptionOverflowError(Exception):
    """Signals that a client must reconnect and replay from SQLite."""

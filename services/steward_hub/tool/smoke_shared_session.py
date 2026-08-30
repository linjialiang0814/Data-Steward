"""Deterministic smoke test for the file-backed shared-session core."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from steward_hub import ConversationEvent, EventStore


def semantic_projection_hash(events: list[ConversationEvent]) -> str:
    canonical = json.dumps(
        [
            {
                "actor_device_id": event.actor_device_id,
                "causation_id": event.causation_id,
                "correlation_id": event.correlation_id,
                "conversation_seq": event.conversation_seq,
                "event_type": event.event_type,
                "payload": {
                    field: json.loads(event.payload_json)[field]
                    for field in (
                        "accepted_seq",
                        "client_message_id",
                        "content",
                        "role",
                    )
                },
                "protocol_version": event.protocol_version,
            }
            for event in events
        ],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def main() -> None:
    devices = ("windows", "phone", "pad")
    with tempfile.TemporaryDirectory() as temporary_directory:
        database_path = Path(temporary_directory) / "smoke.sqlite3"
        store = EventStore(database_path)
        conversation_id = "smoke-shared-session"
        store.create_conversation(
            "Smoke shared session",
            conversation_id=conversation_id,
        )

        submitted_count = 0
        deduplicated_count = 0
        for number in range(1, 21):
            result = store.append_message(
                conversation_id=conversation_id,
                client_message_id=f"smoke-client-{number}",
                actor_device_id=devices[(number - 1) % len(devices)],
                role="user",
                content=f"smoke-message-{number}",
            )
            submitted_count += 1
            deduplicated_count += int(result.deduplicated)

        duplicate = store.append_message(
            conversation_id=conversation_id,
            client_message_id="smoke-client-20",
            actor_device_id=devices[(20 - 1) % len(devices)],
            role="user",
            content="smoke-message-20",
        )
        submitted_count += 1
        deduplicated_count += int(duplicate.deduplicated)

        events = store.replay_events(
            conversation_id=conversation_id,
            after_seq=0,
            limit=100,
        )
        stored_count = store.count_records(conversation_id)[1]
        projections = []
        for prefix_length in (0, 7, 14):
            prefix = events[:prefix_length]
            cursor = (
                prefix[-1].conversation_seq
                if prefix
                else 0
            )
            replayed = store.replay_events(
                conversation_id=conversation_id,
                after_seq=cursor,
                limit=100,
            )
            projections.append(prefix + replayed)
        initial_hash = semantic_projection_hash(events)
        store.close()

        reopened = EventStore(database_path)
        reopened_events = reopened.replay_events(
            conversation_id=conversation_id,
            after_seq=0,
            limit=100,
        )
        reopened_hash = semantic_projection_hash(reopened_events)
        reopened.close()

        summary = {
            "converged": all(projection == events for projection in projections),
            "deduplicated_count": deduplicated_count,
            "first_seq": events[0].conversation_seq if events else None,
            "last_seq": events[-1].conversation_seq if events else None,
            "persisted_round_trip_equal": events == reopened_events,
            "reopened_semantic_projection_hash": reopened_hash,
            "semantic_projection_hash": initial_hash,
            "stored_count": stored_count,
            "submitted_count": submitted_count,
        }
        print(
            json.dumps(
                summary,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()

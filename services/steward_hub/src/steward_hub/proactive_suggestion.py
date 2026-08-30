"""Durable, opt-in Hermes suggestions that never execute side effects."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Protocol, Sequence

from .agent_planning import AgentPlanningError, TypedActionProposal
from .autonomy_job import AutonomyJobError, AutonomyJobStore
from .catalog_clustering import build_today_materials
from .catalog_store import CatalogStore, CatalogStoreError
from .cluster_organization import (
    ClusterOrganizationError,
    ClusterOrganizationService,
)
from .knowledge_pack import KnowledgeContextBuilder, KnowledgePackError

PROACTIVE_ACTION_SCHEMA = "data-steward.proactive-action-card/v1"
PROACTIVE_SCHEMA_VERSION = 1
STABLE_SNAPSHOT_MS = 10_000
SUGGESTION_COOLDOWN_MS = 30 * 60 * 1000
DAILY_SUGGESTION_LIMIT = 3
DAILY_DISMISS_PAUSE_THRESHOLD = 2
ALLOWED_ACTION_TYPES = frozenset(
    {"organize_selected", "export_knowledge_pack"}
)
ALLOWED_CATEGORIES = frozenset({"organization", "knowledge_pack"})

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SUGGESTION_ID_RE = re.compile(r"^ps-[0-9a-f]{20}$")
_TARGET_REF_RE = re.compile(r"^(?:cl-[0-9a-f]{16}|learning|meeting|project|general)$")


class ProactiveSuggestionError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class TypedActionPlanner(Protocol):
    def propose_typed_action(
        self,
        *,
        snapshot_sha256: str,
        candidates: Sequence[dict[str, object]],
    ) -> TypedActionProposal: ...


@dataclass(frozen=True, slots=True)
class SuggestionSettings:
    enabled: bool
    disabled_categories: tuple[str, ...]

    def wire(self) -> dict[str, object]:
        return {
            "schema_version": PROACTIVE_ACTION_SCHEMA,
            "enabled": self.enabled,
            "disabled_categories": list(self.disabled_categories),
        }


@dataclass(frozen=True, slots=True)
class SuggestionCandidate:
    action_type: str
    category: str
    target_ref: str
    title_hint: str
    reason_hint: str
    request: str
    required_capabilities: tuple[str, ...]
    cited_asset_ids: tuple[str, ...]

    def model_wire(self) -> dict[str, object]:
        return {
            "action_type": self.action_type,
            "category": self.category,
            "target_ref": self.target_ref,
            "title_hint": self.title_hint,
            "reason_hint": self.reason_hint,
            "request": self.request,
            "required_capabilities": list(self.required_capabilities),
            "cited_asset_ids": list(self.cited_asset_ids),
        }


@dataclass(frozen=True, slots=True)
class ProactiveSuggestion:
    suggestion_id: str
    action_type: str
    category: str
    target_ref: str
    title: str
    reason: str
    request: str
    source: str
    status: str
    created_at: str

    def wire(self) -> dict[str, object]:
        # target_ref is intentionally private. Clients route through an opaque
        # suggestion ID and receive a safe action target only after acceptance.
        return {
            "schema_version": PROACTIVE_ACTION_SCHEMA,
            "suggestion_id": self.suggestion_id,
            "action_type": self.action_type,
            "category": self.category,
            "title": self.title,
            "reason": self.reason,
            "request": self.request,
            "source": self.source,
            "status": self.status,
            "created_at": self.created_at,
        }

    def accepted_wire(self) -> dict[str, object]:
        value = self.wire()
        value["action_target"] = self.target_ref
        return value


@dataclass(frozen=True, slots=True)
class SuggestionObservation:
    state: str
    suggestions: tuple[ProactiveSuggestion, ...]
    message_key: str

    def wire(self) -> dict[str, object]:
        return {
            "schema_version": PROACTIVE_ACTION_SCHEMA,
            "state": self.state,
            "message_key": self.message_key,
            "suggestions": [item.wire() for item in self.suggestions],
        }


class ProactiveSuggestionStore:
    """Content-free trigger/inbox state sharing the Hub SQLite database."""

    def __init__(self, database_path: str | Path) -> None:
        self._lock = threading.RLock()
        self._closed = False
        try:
            self._connection = sqlite3.connect(
                str(database_path),
                isolation_level=None,
                check_same_thread=False,
                timeout=5.0,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._initialize()
        except ProactiveSuggestionError:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise
        except sqlite3.Error:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise ProactiveSuggestionError("suggestion_persistence_unavailable") from None

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._connection.close()

    def settings(self) -> SuggestionSettings:
        with self._lock:
            row = self._connection.execute(
                "SELECT enabled,disabled_categories_json FROM proactive_settings WHERE singleton=1"
            ).fetchone()
        if row is None:
            raise ProactiveSuggestionError("suggestion_persistence_unavailable")
        disabled = _strict_string_list(str(row["disabled_categories_json"]))
        if any(item not in ALLOWED_CATEGORIES for item in disabled):
            raise ProactiveSuggestionError("suggestion_persistence_unavailable")
        return SuggestionSettings(bool(row["enabled"]), tuple(disabled))

    def update_settings(
        self, *, enabled: bool, disabled_categories: Sequence[str]
    ) -> SuggestionSettings:
        if not isinstance(enabled, bool):
            raise ProactiveSuggestionError("suggestion_request_invalid")
        disabled = _validate_categories(disabled_categories)
        encoded = _canonical_json(list(disabled)).decode("utf-8")
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute(
                    "UPDATE proactive_settings SET enabled=?,disabled_categories_json=?,updated_at=? WHERE singleton=1",
                    (int(enabled), encoded, _utc_now()),
                )
            except sqlite3.Error:
                raise ProactiveSuggestionError(
                    "suggestion_persistence_unavailable"
                ) from None
        return SuggestionSettings(enabled, disabled)

    def inbox(self) -> tuple[ProactiveSuggestion, ...]:
        with self._lock:
            self._ensure_open()
            rows = self._connection.execute(
                "SELECT * FROM proactive_suggestion WHERE status='available' ORDER BY created_ms DESC LIMIT 10"
            ).fetchall()
        return tuple(_suggestion_from_row(row) for row in rows)

    def blocked_categories(self, *, now_ms: int) -> frozenset[str]:
        day_key = _day_key(now_ms)
        settings = self.settings()
        blocked = set(settings.disabled_categories)
        with self._lock:
            self._ensure_open()
            rows = self._connection.execute(
                "SELECT category FROM proactive_category_state WHERE paused_day=?",
                (day_key,),
            ).fetchall()
        blocked.update(str(row["category"]) for row in rows)
        return frozenset(blocked)

    def gate(
        self,
        *,
        snapshot_sha256: str,
        candidate_digest: str,
        candidate_categories: Sequence[str],
        now_ms: int,
    ) -> str:
        _require_digest(snapshot_sha256)
        _require_digest(candidate_digest)
        categories = _validate_categories(candidate_categories)
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
            raise ProactiveSuggestionError("suggestion_request_invalid")
        day_key = _day_key(now_ms)
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                settings = self._connection.execute(
                    "SELECT * FROM proactive_settings WHERE singleton=1"
                ).fetchone()
                if settings is None:
                    raise ProactiveSuggestionError(
                        "suggestion_persistence_unavailable"
                    )
                if not bool(settings["enabled"]):
                    self._connection.commit()
                    return "disabled"
                disabled = set(
                    _strict_string_list(str(settings["disabled_categories_json"]))
                )
                if categories and all(item in disabled for item in categories):
                    self._connection.commit()
                    return "category_paused"
                existing = self._connection.execute(
                    "SELECT status FROM proactive_suggestion WHERE snapshot_sha256=? AND candidate_digest=?",
                    (snapshot_sha256, candidate_digest),
                ).fetchone()
                if existing is not None:
                    self._connection.commit()
                    return (
                        "ready" if str(existing["status"]) == "available" else "handled"
                    )
                observation = self._connection.execute(
                    "SELECT snapshot_sha256,candidate_digest,first_seen_ms FROM proactive_observation WHERE singleton=1"
                ).fetchone()
                if (
                    observation is None
                    or str(observation["snapshot_sha256"]) != snapshot_sha256
                    or str(observation["candidate_digest"]) != candidate_digest
                ):
                    self._connection.execute(
                        "INSERT INTO proactive_observation(singleton,snapshot_sha256,candidate_digest,first_seen_ms) VALUES(1,?,?,?) "
                        "ON CONFLICT(singleton) DO UPDATE SET snapshot_sha256=excluded.snapshot_sha256,candidate_digest=excluded.candidate_digest,first_seen_ms=excluded.first_seen_ms",
                        (snapshot_sha256, candidate_digest, now_ms),
                    )
                    self._connection.commit()
                    return "stabilizing"
                if now_ms - int(observation["first_seen_ms"]) < STABLE_SNAPSHOT_MS:
                    self._connection.commit()
                    return "stabilizing"
                last_created = settings["last_created_ms"]
                if last_created is not None and now_ms - int(last_created) < SUGGESTION_COOLDOWN_MS:
                    self._connection.commit()
                    return "cooldown"
                count = (
                    int(settings["day_count"])
                    if str(settings["day_key"] or "") == day_key
                    else 0
                )
                if count >= DAILY_SUGGESTION_LIMIT:
                    self._connection.commit()
                    return "daily_limit"
                for category in categories:
                    row = self._connection.execute(
                        "SELECT paused_day FROM proactive_category_state WHERE category=?",
                        (category,),
                    ).fetchone()
                    if row is not None and str(row["paused_day"] or "") == day_key:
                        self._connection.commit()
                        return "category_paused"
                self._connection.commit()
                return "eligible"
            except ProactiveSuggestionError:
                self._connection.rollback()
                raise
            except (sqlite3.Error, ValueError, json.JSONDecodeError):
                self._connection.rollback()
                raise ProactiveSuggestionError(
                    "suggestion_persistence_unavailable"
                ) from None

    def create(
        self,
        *,
        snapshot_sha256: str,
        candidate_digest: str,
        proposal: TypedActionProposal,
        now_ms: int,
    ) -> ProactiveSuggestion:
        _require_digest(snapshot_sha256)
        _require_digest(candidate_digest)
        _validate_proposal(proposal)
        suggestion_id = "ps-" + secrets.token_hex(10)
        created_at = _utc_from_ms(now_ms)
        day_key = _day_key(now_ms)
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                existing = self._connection.execute(
                    "SELECT * FROM proactive_suggestion WHERE snapshot_sha256=? AND candidate_digest=?",
                    (snapshot_sha256, candidate_digest),
                ).fetchone()
                if existing is not None:
                    self._connection.commit()
                    return _suggestion_from_row(existing)
                self._connection.execute(
                    """
                    INSERT INTO proactive_suggestion(
                      suggestion_id,snapshot_sha256,candidate_digest,action_type,
                      category,target_ref,title,reason,request,source,status,
                      created_ms,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,'hermes','available',?,?,?)
                    """,
                    (
                        suggestion_id,
                        snapshot_sha256,
                        candidate_digest,
                        proposal.action_type,
                        proposal.category,
                        proposal.target_ref,
                        proposal.title,
                        proposal.reason,
                        proposal.request,
                        now_ms,
                        created_at,
                        created_at,
                    ),
                )
                settings = self._connection.execute(
                    "SELECT day_key,day_count FROM proactive_settings WHERE singleton=1"
                ).fetchone()
                count = (
                    int(settings["day_count"])
                    if settings is not None and str(settings["day_key"] or "") == day_key
                    else 0
                )
                self._connection.execute(
                    "UPDATE proactive_settings SET day_key=?,day_count=?,last_created_ms=?,updated_at=? WHERE singleton=1",
                    (day_key, count + 1, now_ms, created_at),
                )
                self._connection.commit()
            except sqlite3.IntegrityError:
                self._connection.rollback()
                row = self._connection.execute(
                    "SELECT * FROM proactive_suggestion WHERE snapshot_sha256=? AND candidate_digest=?",
                    (snapshot_sha256, candidate_digest),
                ).fetchone()
                if row is None:
                    raise ProactiveSuggestionError(
                        "suggestion_persistence_unavailable"
                    ) from None
                return _suggestion_from_row(row)
            except sqlite3.Error:
                self._connection.rollback()
                raise ProactiveSuggestionError(
                    "suggestion_persistence_unavailable"
                ) from None
        return ProactiveSuggestion(
            suggestion_id=suggestion_id,
            action_type=proposal.action_type,
            category=proposal.category,
            target_ref=proposal.target_ref,
            title=proposal.title,
            reason=proposal.reason,
            request=proposal.request,
            source="hermes",
            status="available",
            created_at=created_at,
        )

    def transition(self, suggestion_id: str, *, target: str, now_ms: int) -> ProactiveSuggestion:
        if (
            not isinstance(suggestion_id, str)
            or _SUGGESTION_ID_RE.fullmatch(suggestion_id) is None
            or target not in {"accepted", "dismissed"}
        ):
            raise ProactiveSuggestionError("suggestion_request_invalid")
        day_key = _day_key(now_ms)
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT * FROM proactive_suggestion WHERE suggestion_id=?",
                    (suggestion_id,),
                ).fetchone()
                if row is None:
                    raise ProactiveSuggestionError("suggestion_not_found")
                current = str(row["status"])
                if current == target:
                    self._connection.commit()
                    return _suggestion_from_row(row)
                if current != "available":
                    raise ProactiveSuggestionError("suggestion_closed")
                now = _utc_from_ms(now_ms)
                self._connection.execute(
                    "UPDATE proactive_suggestion SET status=?,updated_at=? WHERE suggestion_id=?",
                    (target, now, suggestion_id),
                )
                category = str(row["category"])
                if target == "accepted":
                    self._connection.execute(
                        "DELETE FROM proactive_category_state WHERE category=?",
                        (category,),
                    )
                else:
                    state = self._connection.execute(
                        "SELECT day_key,dismiss_count FROM proactive_category_state WHERE category=?",
                        (category,),
                    ).fetchone()
                    count = (
                        int(state["dismiss_count"])
                        if state is not None and str(state["day_key"]) == day_key
                        else 0
                    ) + 1
                    paused = day_key if count >= DAILY_DISMISS_PAUSE_THRESHOLD else None
                    self._connection.execute(
                        "INSERT INTO proactive_category_state(category,day_key,dismiss_count,paused_day) VALUES(?,?,?,?) "
                        "ON CONFLICT(category) DO UPDATE SET day_key=excluded.day_key,dismiss_count=excluded.dismiss_count,paused_day=excluded.paused_day",
                        (category, day_key, count, paused),
                    )
                self._connection.commit()
                return _suggestion_from_row(
                    {**dict(row), "status": target, "updated_at": now}
                )
            except ProactiveSuggestionError:
                self._connection.rollback()
                raise
            except sqlite3.Error:
                self._connection.rollback()
                raise ProactiveSuggestionError(
                    "suggestion_persistence_unavailable"
                ) from None

    def disable_category(self, suggestion_id: str) -> SuggestionSettings:
        if not isinstance(suggestion_id, str) or _SUGGESTION_ID_RE.fullmatch(suggestion_id) is None:
            raise ProactiveSuggestionError("suggestion_request_invalid")
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT category FROM proactive_suggestion WHERE suggestion_id=?",
                (suggestion_id,),
            ).fetchone()
        if row is None:
            raise ProactiveSuggestionError("suggestion_not_found")
        settings = self.settings()
        disabled = tuple(sorted({*settings.disabled_categories, str(row["category"])}))
        self.transition(suggestion_id, target="dismissed", now_ms=int(time.time() * 1000))
        return self.update_settings(enabled=settings.enabled, disabled_categories=disabled)

    def _initialize(self) -> None:
        tables = {
            str(row[0])
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'proactive_%'"
            )
        }
        if "proactive_schema_meta" in tables:
            rows = list(
                self._connection.execute(
                    "SELECT component,schema_version FROM proactive_schema_meta"
                )
            )
            if (
                len(rows) != 1
                or str(rows[0][0]) != "proactive_suggestion"
                or int(rows[0][1]) != PROACTIVE_SCHEMA_VERSION
            ):
                raise ProactiveSuggestionError("suggestion_schema_unsupported")
        elif tables:
            raise ProactiveSuggestionError("suggestion_schema_unsupported")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS proactive_schema_meta(
              component TEXT PRIMARY KEY,
              schema_version INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS proactive_settings(
              singleton INTEGER PRIMARY KEY CHECK(singleton=1),
              enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
              disabled_categories_json TEXT NOT NULL CHECK(length(disabled_categories_json)<=256),
              day_key TEXT,
              day_count INTEGER NOT NULL DEFAULT 0 CHECK(day_count BETWEEN 0 AND 3),
              last_created_ms INTEGER,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS proactive_observation(
              singleton INTEGER PRIMARY KEY CHECK(singleton=1),
              snapshot_sha256 TEXT NOT NULL CHECK(length(snapshot_sha256)=64 AND snapshot_sha256 NOT GLOB '*[^0-9a-f]*'),
              candidate_digest TEXT NOT NULL CHECK(length(candidate_digest)=64 AND candidate_digest NOT GLOB '*[^0-9a-f]*'),
              first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms>=0)
            );
            CREATE TABLE IF NOT EXISTS proactive_category_state(
              category TEXT PRIMARY KEY CHECK(category IN ('organization','knowledge_pack')),
              day_key TEXT NOT NULL,
              dismiss_count INTEGER NOT NULL CHECK(dismiss_count>=0),
              paused_day TEXT
            );
            CREATE TABLE IF NOT EXISTS proactive_suggestion(
              suggestion_id TEXT PRIMARY KEY CHECK(length(suggestion_id)=23 AND substr(suggestion_id,1,3)='ps-' AND substr(suggestion_id,4) NOT GLOB '*[^0-9a-f]*'),
              snapshot_sha256 TEXT NOT NULL CHECK(length(snapshot_sha256)=64 AND snapshot_sha256 NOT GLOB '*[^0-9a-f]*'),
              candidate_digest TEXT NOT NULL CHECK(length(candidate_digest)=64 AND candidate_digest NOT GLOB '*[^0-9a-f]*'),
              action_type TEXT NOT NULL CHECK(action_type IN ('organize_selected','export_knowledge_pack')),
              category TEXT NOT NULL CHECK(category IN ('organization','knowledge_pack')),
              target_ref TEXT NOT NULL CHECK(length(target_ref) BETWEEN 3 AND 64),
              title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 80),
              reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 240),
              request TEXT NOT NULL CHECK(length(request) BETWEEN 1 AND 500),
              source TEXT NOT NULL CHECK(source='hermes'),
              status TEXT NOT NULL CHECK(status IN ('available','accepted','dismissed')),
              created_ms INTEGER NOT NULL CHECK(created_ms>=0),
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE(snapshot_sha256,candidate_digest)
            );
            """
        )
        self._connection.execute(
            "INSERT OR IGNORE INTO proactive_schema_meta VALUES('proactive_suggestion',?)",
            (PROACTIVE_SCHEMA_VERSION,),
        )
        self._connection.execute(
            "INSERT OR IGNORE INTO proactive_settings(singleton,enabled,disabled_categories_json,updated_at) VALUES(1,0,'[]',?)",
            (_utc_now(),),
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise ProactiveSuggestionError("suggestion_store_closed")


class ProactiveSuggestionService:
    def __init__(
        self,
        *,
        store: ProactiveSuggestionStore,
        autonomy: AutonomyJobStore,
        catalog: CatalogStore,
        organization: ClusterOrganizationService,
        knowledge: KnowledgeContextBuilder,
        planner: TypedActionPlanner | None,
        now_ms: Callable[[], int] | None = None,
    ) -> None:
        self.store = store
        self._autonomy = autonomy
        self._catalog = catalog
        self._organization = organization
        self._knowledge = knowledge
        self._planner = planner
        self._now_ms = now_ms or (lambda: int(time.time() * 1000))

    def observe(self) -> SuggestionObservation:
        now_ms = int(self._now_ms())
        try:
            roots, assets, snapshot = self._catalog.current_view()
            today = build_today_materials(
                roots=roots,
                assets=assets,
                source_projection_sha256=snapshot,
                now_ms=now_ms,
            )
        except (CatalogStoreError, ValueError):
            raise ProactiveSuggestionError("suggestion_snapshot_unavailable") from None
        candidates: list[SuggestionCandidate] = []
        for cluster in today.clusters[:3]:
            try:
                preview = self._organization.preview(
                    cluster_id=cluster.cluster_id,
                    projection_sha256=today.projection_sha256,
                )
            except ClusterOrganizationError:
                continue
            candidates.append(
                SuggestionCandidate(
                    action_type="organize_selected",
                    category="organization",
                    target_ref=cluster.cluster_id,
                    title_hint=f"整理{cluster.title}",
                    reason_hint=(cluster.reasons[0] if cluster.reasons else "这些资料可能属于同一事项"),
                    request=f"预览整理 {preview.pc_file_count} 个电脑文件",
                    required_capabilities=("catalog.sync", "files.organize"),
                    cited_asset_ids=tuple(
                        item.asset_id for item in cluster.assets[:12]
                    ),
                )
            )
        try:
            pack = self._knowledge.build("learning")
        except KnowledgePackError:
            pack = None
        if pack is not None:
            candidates.append(
                SuggestionCandidate(
                    action_type="export_knowledge_pack",
                    category="knowledge_pack",
                    target_ref="learning",
                    title_hint="生成跨设备复习资料包",
                    reason_hint="当前资料已形成可引用的学习主题和复习步骤",
                    request="请结合当前跨设备资料生成学习资料包",
                    required_capabilities=("artifact.export", "content.analyze"),
                    cited_asset_ids=tuple(item.asset_id for item in pack.citations),
                )
            )
        if not candidates:
            return SuggestionObservation(
                "unavailable", self.store.inbox(), "suggestion_no_candidate"
            )
        blocked = self.store.blocked_categories(now_ms=now_ms)
        candidates = [item for item in candidates if item.category not in blocked]
        if not candidates:
            state = "disabled" if not self.store.settings().enabled else "category_paused"
            return SuggestionObservation(state, self.store.inbox(), f"suggestion_{state}")
        candidate_wire = [item.model_wire() for item in candidates]
        digest = hashlib.sha256(_canonical_json(candidate_wire)).hexdigest()
        gate = self.store.gate(
            snapshot_sha256=snapshot,
            candidate_digest=digest,
            candidate_categories=tuple(item.category for item in candidates),
            now_ms=now_ms,
        )
        if gate == "ready":
            return SuggestionObservation("ready", self.store.inbox(), "suggestion_ready")
        if gate != "eligible":
            return SuggestionObservation(gate, self.store.inbox(), f"suggestion_{gate}")
        planner = self._planner
        if planner is None:
            return SuggestionObservation("unavailable", self.store.inbox(), "suggestion_agent_unavailable")
        lease = None
        try:
            lease = self._autonomy.begin(
                snapshot_sha256=snapshot,
                normalized_request="proactive-action-card-v1:" + digest,
            )
            if lease.cached_result is not None:
                return SuggestionObservation("ready", self.store.inbox(), "suggestion_ready")
            self._autonomy.transition(lease.job_id, expected="QUEUED", target="SNAPSHOT_BOUND")
            self._autonomy.transition(lease.job_id, expected="SNAPSHOT_BOUND", target="RUNNING")
            proposal = planner.propose_typed_action(
                snapshot_sha256=snapshot,
                candidates=candidate_wire,
            )
            matching = next(
                (
                    item
                    for item in candidates
                    if item.action_type == proposal.action_type
                    and item.category == proposal.category
                    and item.target_ref == proposal.target_ref
                ),
                None,
            )
            if matching is None or not set(proposal.cited_asset_ids).issubset(
                matching.cited_asset_ids
            ):
                raise ProactiveSuggestionError("suggestion_proposal_invalid")
            self._autonomy.transition(lease.job_id, expected="RUNNING", target="VALIDATING")
            created = self.store.create(
                snapshot_sha256=snapshot,
                candidate_digest=digest,
                proposal=proposal,
                now_ms=now_ms,
            )
            self._autonomy.complete(
                lease.job_id,
                state="SUCCEEDED",
                result={
                    "schema_version": PROACTIVE_ACTION_SCHEMA,
                    "suggestion_id": created.suggestion_id,
                    "action_type": created.action_type,
                    "source": "hermes",
                },
            )
            return SuggestionObservation("ready", self.store.inbox(), "suggestion_ready")
        except (AgentPlanningError, AutonomyJobError, ProactiveSuggestionError):
            if lease is not None:
                try:
                    self._autonomy.fail_safe(lease.job_id)
                except AutonomyJobError:
                    pass
            return SuggestionObservation(
                "unavailable", self.store.inbox(), "suggestion_generation_failed"
            )

    def accept(self, suggestion_id: str) -> ProactiveSuggestion:
        return self.store.transition(
            suggestion_id, target="accepted", now_ms=int(self._now_ms())
        )

    def dismiss(self, suggestion_id: str) -> ProactiveSuggestion:
        return self.store.transition(
            suggestion_id, target="dismissed", now_ms=int(self._now_ms())
        )


def _suggestion_from_row(row: object) -> ProactiveSuggestion:
    value = row if isinstance(row, dict) else dict(row)  # type: ignore[arg-type]
    suggestion = ProactiveSuggestion(
        suggestion_id=str(value["suggestion_id"]),
        action_type=str(value["action_type"]),
        category=str(value["category"]),
        target_ref=str(value["target_ref"]),
        title=str(value["title"]),
        reason=str(value["reason"]),
        request=str(value["request"]),
        source=str(value["source"]),
        status=str(value["status"]),
        created_at=str(value["created_at"]),
    )
    _validate_suggestion(suggestion)
    return suggestion


def _validate_suggestion(value: ProactiveSuggestion) -> None:
    if (
        _SUGGESTION_ID_RE.fullmatch(value.suggestion_id) is None
        or value.action_type not in ALLOWED_ACTION_TYPES
        or value.category not in ALLOWED_CATEGORIES
        or _TARGET_REF_RE.fullmatch(value.target_ref) is None
        or value.source != "hermes"
        or value.status not in {"available", "accepted", "dismissed"}
    ):
        raise ProactiveSuggestionError("suggestion_persistence_unavailable")
    _safe_text(value.title, 80)
    _safe_text(value.reason, 240)
    _safe_text(value.request, 500)


def _validate_proposal(value: TypedActionProposal) -> None:
    if (
        value.action_type not in ALLOWED_ACTION_TYPES
        or value.category not in ALLOWED_CATEGORIES
        or _TARGET_REF_RE.fullmatch(value.target_ref) is None
        or not value.cited_asset_ids
    ):
        raise ProactiveSuggestionError("suggestion_proposal_invalid")
    _safe_text(value.title, 80)
    _safe_text(value.reason, 240)
    _safe_text(value.request, 500)


def _safe_text(value: object, limit: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > limit
        or any(ord(char) < 32 for char in value)
        or "content://" in value.casefold()
        or re.search(r"(?:[A-Za-z]:\\|\\\\|/Users/|/home/)", value)
    ):
        raise ProactiveSuggestionError("suggestion_proposal_invalid")
    return value.strip()


def _validate_categories(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ProactiveSuggestionError("suggestion_request_invalid")
    result = tuple(sorted(set(values)))
    if len(result) > len(ALLOWED_CATEGORIES) or any(
        not isinstance(item, str) or item not in ALLOWED_CATEGORIES for item in result
    ):
        raise ProactiveSuggestionError("suggestion_request_invalid")
    return result


def _strict_string_list(raw: str) -> list[str]:
    value = json.loads(raw)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("not_string_list")
    return value


def _require_digest(value: str) -> None:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ProactiveSuggestionError("suggestion_request_invalid")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _day_key(value_ms: int) -> str:
    return datetime.fromtimestamp(value_ms / 1000, UTC).date().isoformat()


def _utc_from_ms(value_ms: int) -> str:
    return datetime.fromtimestamp(value_ms / 1000, UTC).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")

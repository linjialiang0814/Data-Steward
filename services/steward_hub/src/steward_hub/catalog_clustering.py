"""Deterministic metadata-only clustering for the Today Materials projection."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import PurePath
from typing import Iterable

from .catalog_models import CatalogAssetView, CatalogRootView

TODAY_SCHEMA = "data-steward.today-materials/v1"
CLUSTER_RULE_VERSION = "time-name-v1"
DEFAULT_TIMEZONE_OFFSET_MINUTES = 480
TIME_WINDOW_MS = 120 * 60 * 1000
HIGH_CONFIDENCE = 800
MEDIUM_CONFIDENCE = 550
MAX_REASON_COUNT = 3

_WORD_RE = re.compile(r"[a-z]+|\d+|[\u3400-\u9fff]+")
_LOW_INFORMATION = frozenset(
    {
        "copy",
        "final",
        "new",
        "old",
        "副本",
        "最终",
        "新版",
        "文件",
        "资料",
        "document",
        "file",
        "v",
    }
)
_ROLE_TERMS = (
    "courseware",
    "lecture",
    "slides",
    "slide",
    "notes",
    "note",
    "homework",
    "assignment",
    "photo",
    "image",
    "recording",
    "课件",
    "课堂",
    "讲义",
    "笔记",
    "作业",
    "照片",
    "图片",
    "录音",
    "截图",
)
_TOPICS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("higher-math", "高等数学", ("高等数学", "高数", "highermath", "calculus")),
    ("math", "数学", ("数学", "math", "mathematics")),
    ("english", "英语", ("英语", "english")),
    ("data-structures", "数据结构", ("数据结构", "datastructure", "data structures")),
    ("computer", "计算机", ("计算机", "computer", "computing", "cs")),
    ("meeting", "会议", ("会议", "meeting", "minutes")),
    ("client", "客户事项", ("客户", "client", "customer")),
    ("project", "项目资料", ("项目", "project")),
)


class CatalogClusteringError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TodayAssetView:
    asset_id: str
    display_name: str
    platform: str
    source_display_name: str
    mime_family: str
    effective_at_ms: int
    time_source: str


@dataclass(frozen=True, slots=True)
class TodayClusterView:
    cluster_id: str
    title: str
    start_at_ms: int
    end_at_ms: int
    source_platforms: tuple[str, ...]
    mime_families: tuple[str, ...]
    asset_count: int
    confidence_permille: int
    confidence_band: str
    reasons: tuple[str, ...]
    assets: tuple[TodayAssetView, ...]


@dataclass(frozen=True, slots=True)
class TodayMaterialsProjection:
    schema_version: str
    rule_version: str
    local_day: str
    timezone_offset_minutes: int
    source_projection_sha256: str
    root_count: int
    asset_count: int
    cluster_count: int
    unassigned_count: int
    clusters: tuple[TodayClusterView, ...]
    unassigned: tuple[TodayAssetView, ...]
    projection_sha256: str

    def wire(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class _Feature:
    asset: TodayAssetView
    tokens: frozenset[str]
    topic_key: str | None
    topic_label: str | None


def build_today_materials(
    *,
    roots: Iterable[CatalogRootView],
    assets: Iterable[CatalogAssetView],
    source_projection_sha256: str,
    now_ms: int,
    timezone_offset_minutes: int = DEFAULT_TIMEZONE_OFFSET_MINUTES,
) -> TodayMaterialsProjection:
    if not re.fullmatch(r"[0-9a-f]{64}", source_projection_sha256):
        raise CatalogClusteringError("catalog_integrity_error")
    if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
        raise CatalogClusteringError("catalog_time_invalid")
    if not -720 <= timezone_offset_minutes <= 840:
        raise CatalogClusteringError("catalog_timezone_invalid")
    root_rows = tuple(roots)
    asset_rows = tuple(assets)
    local_day = _local_day(now_ms, timezone_offset_minutes)
    features = tuple(
        sorted(
            (
                feature
                for item in asset_rows
                if (feature := _feature(item)).asset
                and _local_day(feature.asset.effective_at_ms, timezone_offset_minutes)
                == local_day
            ),
            key=lambda value: (value.asset.effective_at_ms, value.asset.asset_id),
        )
    )
    parent = list(range(len(features)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root == right_root:
            return
        if left_root < right_root:
            parent[right_root] = left_root
        else:
            parent[left_root] = right_root

    pair_scores: dict[tuple[int, int], int] = {}
    for left in range(len(features)):
        for right in range(left + 1, len(features)):
            score = _pair_score(features[left], features[right])
            pair_scores[(left, right)] = score
            if score >= MEDIUM_CONFIDENCE:
                union(left, right)

    grouped: dict[int, list[int]] = {}
    for index in range(len(features)):
        grouped.setdefault(find(index), []).append(index)

    clusters: list[TodayClusterView] = []
    unassigned: list[TodayAssetView] = []
    for indexes in grouped.values():
        if len(indexes) < 2:
            unassigned.append(features[indexes[0]].asset)
            continue
        confidence = _group_confidence(indexes, pair_scores)
        if confidence < MEDIUM_CONFIDENCE:
            unassigned.extend(features[index].asset for index in indexes)
            continue
        clusters.append(
            _cluster(
                indexes,
                features,
                pair_scores,
                confidence,
                timezone_offset_minutes,
            )
        )

    clusters.sort(key=lambda value: (-value.end_at_ms, value.cluster_id))
    unassigned.sort(key=lambda value: (-value.effective_at_ms, value.asset_id))
    projection = TodayMaterialsProjection(
        schema_version=TODAY_SCHEMA,
        rule_version=CLUSTER_RULE_VERSION,
        local_day=local_day,
        timezone_offset_minutes=timezone_offset_minutes,
        source_projection_sha256=source_projection_sha256,
        root_count=len(root_rows),
        asset_count=len(features),
        cluster_count=len(clusters),
        unassigned_count=len(unassigned),
        clusters=tuple(clusters),
        unassigned=tuple(unassigned),
        projection_sha256="0" * 64,
    )
    wire = asdict(projection)
    wire.pop("projection_sha256")
    digest = hashlib.sha256(
        json.dumps(wire, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    ).hexdigest()
    return replace(projection, projection_sha256=digest)


def _feature(item: CatalogAssetView) -> _Feature:
    observed_ms = _parse_observed(item.observed_at)
    modified = item.modified_at_ms
    reliable = (
        modified is not None
        and 0 <= modified < 2**63
        and abs(modified - observed_ms) <= 36 * 60 * 60 * 1000
    )
    effective = modified if reliable else observed_ms
    topic_key, topic_label = _topic(item.display_name)
    return _Feature(
        asset=TodayAssetView(
            asset_id=item.asset_id,
            display_name=item.display_name,
            platform=item.platform,
            source_display_name=item.source_display_name,
            mime_family=item.mime_family,
            effective_at_ms=effective,
            time_source="modified" if reliable else "observed",
        ),
        tokens=frozenset(_tokens(item.display_name)),
        topic_key=topic_key,
        topic_label=topic_label,
    )


def _pair_score(left: _Feature, right: _Feature) -> int:
    distance = abs(left.asset.effective_at_ms - right.asset.effective_at_ms)
    if distance > TIME_WINDOW_MS or (
        left.topic_key is not None
        and right.topic_key is not None
        and left.topic_key != right.topic_key
    ):
        return 0
    score = 400 if distance <= 30 * 60 * 1000 else 300
    shared = left.tokens & right.tokens
    if shared:
        score += min(450, 350 + 50 * (len(shared) - 1))
    if left.topic_key is not None and left.topic_key == right.topic_key:
        score += 300
    if left.asset.platform != right.asset.platform:
        score += 100
    if left.asset.mime_family != right.asset.mime_family:
        score += 100
    return min(1000, score)


def _group_confidence(
    indexes: list[int], pair_scores: dict[tuple[int, int], int]
) -> int:
    best: list[int] = []
    for index in indexes:
        candidates = [
            pair_scores[tuple(sorted((index, other)))]
            for other in indexes
            if other != index
        ]
        best.append(max(candidates))
    return sum(best) // len(best)


def _cluster(
    indexes: list[int],
    features: tuple[_Feature, ...],
    pair_scores: dict[tuple[int, int], int],
    confidence: int,
    timezone_offset_minutes: int,
) -> TodayClusterView:
    selected = tuple(features[index] for index in indexes)
    assets = tuple(
        sorted(
            (feature.asset for feature in selected),
            key=lambda value: (value.effective_at_ms, value.asset_id),
        )
    )
    topic_labels = sorted(
        {feature.topic_label for feature in selected if feature.topic_label is not None}
    )
    common_tokens = set(selected[0].tokens)
    for feature in selected[1:]:
        common_tokens &= feature.tokens
    title = (
        f"{topic_labels[0]}资料"
        if topic_labels
        else f"{sorted(common_tokens)[0]}资料"
        if common_tokens
        else _period_title(assets[0].effective_at_ms, timezone_offset_minutes)
    )
    reasons: list[str] = []
    if topic_labels or common_tokens:
        reasons.append("文件名包含相同课程或事项关键词")
    if assets[-1].effective_at_ms - assets[0].effective_at_ms <= TIME_WINDOW_MS:
        reasons.append("这些资料在两小时内集中出现")
    if len({asset.platform for asset in assets}) > 1:
        reasons.append("资料来自手机和电脑")
    if len({asset.mime_family for asset in assets}) > 1:
        reasons.append("文件类型互补，可能属于同一学习或工作事项")
    cluster_seed = "\0".join(
        (CLUSTER_RULE_VERSION, *(asset.asset_id for asset in sorted(assets, key=lambda a: a.asset_id)))
    )
    return TodayClusterView(
        cluster_id="cl-" + hashlib.sha256(cluster_seed.encode()).hexdigest()[:16],
        title=title,
        start_at_ms=assets[0].effective_at_ms,
        end_at_ms=assets[-1].effective_at_ms,
        source_platforms=tuple(sorted({asset.platform for asset in assets})),
        mime_families=tuple(sorted({asset.mime_family for asset in assets})),
        asset_count=len(assets),
        confidence_permille=confidence,
        confidence_band="high" if confidence >= HIGH_CONFIDENCE else "medium",
        reasons=tuple(reasons[:MAX_REASON_COUNT]),
        assets=assets,
    )


def _tokens(display_name: str) -> tuple[str, ...]:
    stem = PurePath(unicodedata.normalize("NFKC", display_name).casefold()).stem
    cleaned = stem
    for role in _ROLE_TERMS:
        cleaned = cleaned.replace(role, " ")
    values: set[str] = set()
    for token in _WORD_RE.findall(cleaned):
        token = token.strip()
        if (
            len(token) < 2
            or token in _LOW_INFORMATION
            or token.isdigit()
            or re.fullmatch(r"v?\d+", token)
        ):
            continue
        values.add(token)
    topic_key, _ = _topic(stem)
    if topic_key is not None:
        values.add(topic_key)
    return tuple(sorted(values))


def _topic(display_name: str) -> tuple[str | None, str | None]:
    normalized = unicodedata.normalize("NFKC", display_name).casefold().replace("_", " ")
    compact = normalized.replace("-", "").replace(" ", "")
    for key, label, aliases in _TOPICS:
        if any(alias.replace(" ", "") in compact for alias in aliases):
            return key, label
    return None, None


def _parse_observed(value: str) -> int:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return int(parsed.timestamp() * 1000)
    except (TypeError, ValueError, OverflowError):
        raise CatalogClusteringError("catalog_integrity_error") from None


def _local_day(value_ms: int, offset_minutes: int) -> str:
    tz = timezone(timedelta(minutes=offset_minutes))
    return datetime.fromtimestamp(value_ms / 1000, tz=UTC).astimezone(tz).date().isoformat()


def _period_title(value_ms: int, offset_minutes: int) -> str:
    hour = datetime.fromtimestamp(value_ms / 1000, tz=UTC).astimezone(
        timezone(timedelta(minutes=offset_minutes))
    ).hour
    if hour < 6:
        return "凌晨资料"
    if hour < 12:
        return "上午资料"
    if hour < 18:
        return "下午资料"
    return "晚间资料"

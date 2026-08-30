"""Snapshot-bound cross-device knowledge packs and deterministic Markdown."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from .catalog_store import CatalogStore
from .content_understanding import ContentUnderstandingError, ContentUnderstandingService

KNOWLEDGE_PACK_SCHEMA = "data-steward.knowledge-pack/v1"
MAX_KNOWLEDGE_CITATIONS = 12
MAX_KNOWLEDGE_MARKDOWN_BYTES = 128 * 1024
KNOWLEDGE_PACK_KINDS = frozenset({"learning", "meeting", "project", "general"})
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_PACK_ID_RE = re.compile(r"^kp-[0-9a-f]{16}$")
_KIND_LABEL = {
    "learning": "学习资料包",
    "meeting": "会议简报",
    "project": "项目资料包",
    "general": "综合资料包",
}


class KnowledgePackError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class KnowledgeCitation:
    citation_id: str
    platform: str
    source_display_name: str
    display_name: str
    modified_at_ms: int | None
    asset_id: str
    basis: str = "content_projection"

    def wire(self) -> dict[str, Any]:
        return {
            "citation_id": self.citation_id,
            "platform": self.platform,
            "source_display_name": self.source_display_name,
            "display_name": self.display_name,
            "modified_at_ms": self.modified_at_ms,
            "basis": self.basis,
        }


@dataclass(frozen=True, slots=True)
class KnowledgePack:
    pack_id: str
    kind: str
    snapshot_sha256: str
    source_projection_sha256: str
    title: str
    summary: str
    topics: tuple[str, ...]
    review_points: tuple[str, ...]
    citations: tuple[KnowledgeCitation, ...]
    source: str
    cross_device: bool
    created_at: str
    projection_sha256: str

    def wire(self) -> dict[str, Any]:
        return {
            "schema_version": KNOWLEDGE_PACK_SCHEMA,
            "pack_id": self.pack_id,
            "kind": self.kind,
            "title": self.title,
            "summary": self.summary,
            "topics": list(self.topics),
            "review_points": list(self.review_points),
            "citations": [citation.wire() for citation in self.citations],
            "source": self.source,
            "cross_device": self.cross_device,
            "created_at": self.created_at,
            "projection_sha256": self.projection_sha256,
        }


class KnowledgeContextBuilder:
    def __init__(
        self,
        *,
        catalog: CatalogStore,
        content: ContentUnderstandingService,
    ) -> None:
        self._catalog = catalog
        self._content = content

    def build(self, kind: str) -> KnowledgePack:
        if kind not in KNOWLEDGE_PACK_KINDS:
            raise KnowledgePackError("knowledge_pack_kind_invalid")
        try:
            study_pack = self._content.latest_study_pack()
        except ContentUnderstandingError as exc:
            raise KnowledgePackError(exc.code) from None
        if study_pack is None:
            raise KnowledgePackError("knowledge_pack_unavailable")
        _, assets, snapshot = self._catalog.current_view()
        if snapshot != study_pack.snapshot_sha256:
            raise KnowledgePackError("knowledge_pack_snapshot_stale")
        by_id = {asset.asset_id: asset for asset in assets}
        cited = tuple(study_pack.cited_asset_ids)
        if (
            not cited
            or len(cited) > MAX_KNOWLEDGE_CITATIONS
            or len(set(cited)) != len(cited)
            or any(asset_id not in by_id for asset_id in cited)
        ):
            raise KnowledgePackError("knowledge_pack_citation_invalid")
        selected_ids = list(cited)
        basis_by_id = {asset_id: "content_projection" for asset_id in selected_ids}
        available_platforms = {
            asset.platform for asset in assets if asset.platform in {"windows", "android"}
        }
        selected_platforms = {by_id[asset_id].platform for asset_id in selected_ids}
        for platform in sorted(available_platforms - selected_platforms):
            candidates = sorted(
                (
                    asset
                    for asset in assets
                    if asset.platform == platform and asset.asset_id not in basis_by_id
                ),
                key=lambda asset: (
                    not asset.content_eligible,
                    -(asset.modified_at_ms or 0),
                    asset.display_name.casefold(),
                    asset.asset_id,
                ),
            )
            if not candidates:
                continue
            if len(selected_ids) >= MAX_KNOWLEDGE_CITATIONS:
                counts = {
                    value: sum(by_id[item].platform == value for item in selected_ids)
                    for value in selected_platforms
                }
                removable = next(
                    (
                        item
                        for item in reversed(selected_ids)
                        if counts.get(by_id[item].platform, 0) > 1
                    ),
                    None,
                )
                if removable is None:
                    raise KnowledgePackError("knowledge_pack_citation_invalid")
                selected_ids.remove(removable)
                basis_by_id.pop(removable, None)
            selected_ids.append(candidates[0].asset_id)
            basis_by_id[candidates[0].asset_id] = "catalog_metadata"
            selected_platforms.add(platform)
        cited = tuple(selected_ids)
        citations: list[KnowledgeCitation] = []
        for index, asset_id in enumerate(cited, start=1):
            asset = by_id[asset_id]
            if asset.platform not in {"windows", "android"}:
                raise KnowledgePackError("knowledge_pack_citation_invalid")
            citations.append(
                KnowledgeCitation(
                    citation_id=f"S{index}",
                    platform=asset.platform,
                    source_display_name=_safe_text(asset.source_display_name, 80),
                    display_name=_safe_text(asset.display_name, 255),
                    modified_at_ms=asset.modified_at_ms,
                    asset_id=asset.asset_id,
                    basis=basis_by_id[asset_id],
                )
            )
        pack_seed = _canonical_json(
            {
                "kind": kind,
                "snapshot_sha256": snapshot,
                "source_projection_sha256": study_pack.projection_sha256,
                "cited_asset_ids": cited,
            }
        )
        pack_id = "kp-" + hashlib.sha256(pack_seed).hexdigest()[:16]
        title = _bounded_title(_KIND_LABEL[kind], study_pack.title)
        base: dict[str, Any] = {
            "schema_version": KNOWLEDGE_PACK_SCHEMA,
            "pack_id": pack_id,
            "kind": kind,
            "snapshot_sha256": snapshot,
            "source_projection_sha256": study_pack.projection_sha256,
            "title": title,
            "summary": _safe_text(study_pack.summary, 1_200),
            "topics": [_safe_text(item, 80) for item in study_pack.topics],
            "review_points": [
                _safe_text(item, 240) for item in study_pack.review_points
            ],
            "citations": [asdict(item) for item in citations],
            "source": study_pack.source,
            "cross_device": len({item.platform for item in citations}) > 1,
            "created_at": study_pack.created_at,
        }
        projection = hashlib.sha256(_canonical_json(base)).hexdigest()
        return KnowledgePack(
            pack_id=pack_id,
            kind=kind,
            snapshot_sha256=snapshot,
            source_projection_sha256=study_pack.projection_sha256,
            title=title,
            summary=base["summary"],
            topics=tuple(base["topics"]),
            review_points=tuple(base["review_points"]),
            citations=tuple(citations),
            source=study_pack.source,
            cross_device=bool(base["cross_device"]),
            created_at=study_pack.created_at,
            projection_sha256=projection,
        )


def render_knowledge_markdown(pack: KnowledgePack) -> bytes:
    _validate_pack(pack)
    lines = [
        f"# {_escape_markdown(pack.title)}",
        "",
        "## 摘要",
        "",
        _escape_markdown(pack.summary),
        "",
        "## 主题",
        "",
    ]
    lines.extend(f"- {_escape_markdown(item)}" for item in pack.topics)
    lines.extend(["", "## 建议步骤", ""])
    lines.extend(
        f"{index}. {_escape_markdown(item)}"
        for index, item in enumerate(pack.review_points, start=1)
    )
    lines.extend(["", "## 来源", ""])
    for citation in pack.citations:
        platform = "Windows" if citation.platform == "windows" else "Android"
        basis = "正文/安全投影" if citation.basis == "content_projection" else "目录元数据"
        lines.append(
            f"- [{citation.citation_id}] {platform} · "
            f"{_escape_markdown(citation.source_display_name)} · "
            f"{_escape_markdown(citation.display_name)}（{basis}）"
        )
    origin = "Hermes 受控分析" if pack.source == "hermes" else "本机安全摘要"
    lines.extend(
        [
            "",
            "---",
            "",
            f"由 Data Steward 基于当前授权资料生成；分析来源：{origin}。",
            "导出不会修改任何原始资料。",
            "",
        ]
    )
    raw = "\n".join(lines).encode("utf-8")
    if not raw or len(raw) > MAX_KNOWLEDGE_MARKDOWN_BYTES:
        raise KnowledgePackError("knowledge_markdown_too_large")
    return raw


def _validate_pack(pack: KnowledgePack) -> None:
    if (
        not _PACK_ID_RE.fullmatch(pack.pack_id)
        or pack.kind not in KNOWLEDGE_PACK_KINDS
        or not _DIGEST_RE.fullmatch(pack.snapshot_sha256)
        or not _DIGEST_RE.fullmatch(pack.source_projection_sha256)
        or not _DIGEST_RE.fullmatch(pack.projection_sha256)
        or not 1 <= len(pack.citations) <= MAX_KNOWLEDGE_CITATIONS
        or pack.source not in {"hermes", "deterministic_fallback"}
        or any(
            citation.basis not in {"content_projection", "catalog_metadata"}
            for citation in pack.citations
        )
    ):
        raise KnowledgePackError("knowledge_pack_invalid")


def _safe_text(value: object, limit: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > limit
        or any(ord(char) < 32 and char not in {"\n", "\t"} for char in value)
        or "content://" in value.casefold()
        or re.search(r"(?:[A-Za-z]:\\|\\\\|/Users/|/home/)", value)
    ):
        raise KnowledgePackError("knowledge_pack_invalid")
    return value.strip()


def _bounded_title(prefix: str, value: object) -> str:
    source = _safe_text(value, 80)
    available = 80 - len(prefix) - 1
    if available < 1:
        raise KnowledgePackError("knowledge_pack_invalid")
    return f"{prefix}｜{source[:available].rstrip()}"


def _escape_markdown(value: str) -> str:
    escaped = value.replace("\\", "\\\\")
    for char in ("`", "*", "_", "{", "}", "[", "]", "<", ">", "#", "|"):
        escaped = escaped.replace(char, "\\" + char)
    return escaped


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

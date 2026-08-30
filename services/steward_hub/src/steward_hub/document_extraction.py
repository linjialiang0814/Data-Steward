"""Bounded, fail-closed extraction for untrusted office documents and PDFs."""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from pypdf import PdfReader

MAX_DOCUMENT_INPUT_BYTES = 5 * 1024 * 1024
MAX_DOCUMENT_OUTPUT_CHARS = 20_000
MAX_ZIP_ENTRIES = 2_000
MAX_ZIP_EXPANDED_BYTES = 32 * 1024 * 1024
MAX_ZIP_ENTRY_BYTES = 8 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 100
MAX_PDF_PAGES = 120
MAX_PPTX_SLIDES = 300
DEFAULT_DOCUMENT_DEADLINE_SECONDS = 8.0
MAX_WORKER_STDOUT_BYTES = 128 * 1024
MAX_WORKER_STDERR_BYTES = 32 * 1024
SUPPORTED_DOCUMENT_EXTENSIONS = frozenset({"docx", "pptx", "pdf"})

_DIGITS_RE = re.compile(r"(\d+)")
_SAFE_WORKER_CODES = frozenset(
    {
        "content_document_encrypted",
        "content_document_external_reference",
        "content_document_embedded_object",
        "content_document_invalid",
        "content_document_limit_exceeded",
        "content_document_text_layer_missing",
        "content_format_unsupported",
    }
)


class DocumentExtractionError(RuntimeError):
    """Stable, content-free parser failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ExtractedDocument:
    format: str
    text: str
    char_count: int
    truncated: bool
    unit_count: int


class DocumentExtractorSupervisor:
    """Own one parser subprocess per file and always reap it."""

    def __init__(
        self,
        *,
        deadline_seconds: float = DEFAULT_DOCUMENT_DEADLINE_SECONDS,
        python_executable: str | None = None,
        worker_script: Path | None = None,
    ) -> None:
        if not 0.05 <= deadline_seconds <= 30:
            raise ValueError("document_deadline_invalid")
        self._deadline_seconds = float(deadline_seconds)
        self._python_executable = python_executable or sys.executable
        self._worker_script = worker_script or Path(__file__).resolve()

    def extract(
        self, *, extension: str, payload: bytes, max_chars: int
    ) -> ExtractedDocument:
        normalized = _validate_request(extension, payload, max_chars)
        creationflags = (
            subprocess.CREATE_NO_WINDOW
            if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW")
            else 0
        )
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                [
                    self._python_executable,
                    str(self._worker_script),
                    "--worker",
                    normalized,
                    str(max_chars),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=creationflags,
                env=_worker_environment(),
            )
            try:
                stdout, stderr = process.communicate(
                    input=payload, timeout=self._deadline_seconds
                )
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                raise DocumentExtractionError("content_document_timeout") from None
            if (
                process.returncode != 0
                or len(stdout) > MAX_WORKER_STDOUT_BYTES
                or len(stderr) > MAX_WORKER_STDERR_BYTES
            ):
                raise DocumentExtractionError("content_document_parser_crashed")
            return _decode_worker_response(stdout)
        except DocumentExtractionError:
            raise
        except (OSError, ValueError):
            raise DocumentExtractionError("content_document_parser_unavailable") from None
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()


def extract_document_bytes(
    *, extension: str, payload: bytes, max_chars: int
) -> ExtractedDocument:
    normalized = _validate_request(extension, payload, max_chars)
    if normalized == "docx":
        text, units = _extract_docx(payload)
    elif normalized == "pptx":
        text, units = _extract_pptx(payload)
    else:
        text, units = _extract_pdf(payload)
    cleaned = _clean_text(text)
    if not cleaned:
        raise DocumentExtractionError("content_document_text_layer_missing")
    truncated = len(cleaned) > max_chars
    projected = cleaned[:max_chars]
    return ExtractedDocument(
        format=normalized,
        text=projected,
        char_count=len(projected),
        truncated=truncated,
        unit_count=units,
    )


def _extract_docx(payload: bytes) -> tuple[str, int]:
    with _validated_zip(payload) as archive:
        names = set(archive.namelist())
        if "word/document.xml" not in names or "[Content_Types].xml" not in names:
            raise DocumentExtractionError("content_document_invalid")
        _reject_active_or_embedded_content(archive, names, prefix="word")
        _reject_external_relationships(archive)
        root = _safe_xml(archive.read("word/document.xml"))
        paragraphs: list[str] = []
        for node in root.iter():
            if _local_name(node.tag) == "p":
                value = "".join(
                    child.text or ""
                    for child in node.iter()
                    if _local_name(child.tag) in {"t", "tab", "br"}
                )
                if value.strip():
                    paragraphs.append(value)
        return "\n".join(paragraphs), len(paragraphs)


def _extract_pptx(payload: bytes) -> tuple[str, int]:
    with _validated_zip(payload) as archive:
        names = set(archive.namelist())
        if "ppt/presentation.xml" not in names or "[Content_Types].xml" not in names:
            raise DocumentExtractionError("content_document_invalid")
        _reject_active_or_embedded_content(archive, names, prefix="ppt")
        _reject_external_relationships(archive)
        slides = sorted(
            (
                name
                for name in names
                if re.fullmatch(r"ppt/slides/slide\d+\.xml", name)
            ),
            key=_numeric_path_key,
        )
        if not slides or len(slides) > MAX_PPTX_SLIDES:
            raise DocumentExtractionError("content_document_limit_exceeded")
        notes = {
            _numeric_path_key(name)[0]: name
            for name in names
            if re.fullmatch(r"ppt/notesSlides/notesSlide\d+\.xml", name)
        }
        sections: list[str] = []
        for slide in slides:
            values = _xml_text_values(_safe_xml(archive.read(slide)))
            note_name = notes.get(_numeric_path_key(slide)[0])
            if note_name is not None:
                values.extend(_xml_text_values(_safe_xml(archive.read(note_name))))
            if values:
                sections.append("\n".join(values))
        return "\n\n".join(sections), len(slides)


def _extract_pdf(payload: bytes) -> tuple[str, int]:
    try:
        reader = PdfReader(io.BytesIO(payload), strict=True)
        if reader.is_encrypted:
            raise DocumentExtractionError("content_document_encrypted")
        pages = reader.pages
        if not pages or len(pages) > MAX_PDF_PAGES:
            raise DocumentExtractionError("content_document_limit_exceeded")
        if _pdf_has_embedded_files(reader):
            raise DocumentExtractionError("content_document_embedded_object")
        values: list[str] = []
        for page in pages:
            value = page.extract_text() or ""
            if value.strip():
                values.append(value)
        return "\n\n".join(values), len(pages)
    except DocumentExtractionError:
        raise
    except Exception:
        raise DocumentExtractionError("content_document_invalid") from None


def _pdf_has_embedded_files(reader: PdfReader) -> bool:
    try:
        root = reader.trailer.get("/Root")
        if root is None:
            return False
        root_object = root.get_object() if hasattr(root, "get_object") else root
        names = root_object.get("/Names") if hasattr(root_object, "get") else None
        if names is None:
            return False
        names_object = names.get_object() if hasattr(names, "get_object") else names
        return bool(
            hasattr(names_object, "get") and names_object.get("/EmbeddedFiles") is not None
        )
    except Exception:
        raise DocumentExtractionError("content_document_invalid") from None


class _ValidatedZip:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self._archive: zipfile.ZipFile | None = None

    def __enter__(self) -> zipfile.ZipFile:
        try:
            archive = zipfile.ZipFile(io.BytesIO(self._payload), "r")
            self._archive = archive
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ZIP_ENTRIES:
                raise DocumentExtractionError("content_document_limit_exceeded")
            if len({info.filename for info in infos}) != len(infos):
                raise DocumentExtractionError("content_document_invalid")
            total_expanded = 0
            for info in infos:
                _validate_zip_name(info.filename)
                if info.flag_bits & 0x1:
                    raise DocumentExtractionError("content_document_encrypted")
                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode == 0o120000:
                    raise DocumentExtractionError("content_document_invalid")
                if info.file_size > MAX_ZIP_ENTRY_BYTES:
                    raise DocumentExtractionError("content_document_limit_exceeded")
                total_expanded += info.file_size
                if total_expanded > MAX_ZIP_EXPANDED_BYTES:
                    raise DocumentExtractionError("content_document_limit_exceeded")
                if info.file_size > 1_024:
                    compressed = max(info.compress_size, 1)
                    if info.file_size / compressed > MAX_ZIP_COMPRESSION_RATIO:
                        raise DocumentExtractionError("content_document_limit_exceeded")
            return archive
        except DocumentExtractionError:
            if self._archive is not None:
                self._archive.close()
            raise
        except (OSError, zipfile.BadZipFile, RuntimeError):
            raise DocumentExtractionError("content_document_invalid") from None

    def __exit__(self, *_: object) -> None:
        if self._archive is not None:
            self._archive.close()


def _validated_zip(payload: bytes) -> _ValidatedZip:
    return _ValidatedZip(payload)


def _validate_zip_name(name: str) -> None:
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or name.startswith("/")
        or re.match(r"^[A-Za-z]:", name) is not None
    ):
        raise DocumentExtractionError("content_document_invalid")
    parts = PurePosixPath(name).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise DocumentExtractionError("content_document_invalid")


def _reject_active_or_embedded_content(
    archive: zipfile.ZipFile, names: set[str], *, prefix: str
) -> None:
    lowered = {name.casefold() for name in names}
    if any(
        name.endswith("vbaproject.bin")
        or name.startswith(f"{prefix}/embeddings/")
        for name in lowered
    ):
        raise DocumentExtractionError("content_document_embedded_object")
    content_types = archive.read("[Content_Types].xml")
    if b"macroenabled" in content_types.lower():
        raise DocumentExtractionError("content_document_embedded_object")


def _reject_external_relationships(archive: zipfile.ZipFile) -> None:
    for name in archive.namelist():
        if not name.casefold().endswith(".rels"):
            continue
        root = _safe_xml(archive.read(name))
        for node in root.iter():
            if (
                _local_name(node.tag) == "Relationship"
                and node.attrib.get("TargetMode", "").casefold() == "external"
            ):
                raise DocumentExtractionError(
                    "content_document_external_reference"
                )


def _safe_xml(payload: bytes) -> ET.Element:
    lowered = payload.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise DocumentExtractionError("content_document_invalid")
    try:
        return ET.fromstring(payload)
    except ET.ParseError:
        raise DocumentExtractionError("content_document_invalid") from None


def _xml_text_values(root: ET.Element) -> list[str]:
    return [
        node.text
        for node in root.iter()
        if _local_name(node.tag) == "t" and node.text and node.text.strip()
    ]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _numeric_path_key(value: str) -> tuple[int, str]:
    match = _DIGITS_RE.search(value.rsplit("/", 1)[-1])
    return (int(match.group(1)) if match else 0, value)


def _clean_text(value: str) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    if "\x00" in normalized or any(
        ord(char) < 32 and char not in {"\n", "\t"} for char in normalized
    ):
        raise DocumentExtractionError("content_document_invalid")
    lines = [" ".join(line.split()) for line in normalized.split("\n")]
    return "\n".join(line for line in lines if line).strip()


def _validate_request(extension: str, payload: bytes, max_chars: int) -> str:
    normalized = extension.casefold().lstrip(".") if isinstance(extension, str) else ""
    if normalized not in SUPPORTED_DOCUMENT_EXTENSIONS:
        raise DocumentExtractionError("content_format_unsupported")
    if (
        not isinstance(payload, bytes)
        or not payload
        or len(payload) > MAX_DOCUMENT_INPUT_BYTES
        or isinstance(max_chars, bool)
        or not isinstance(max_chars, int)
        or not 1 <= max_chars <= MAX_DOCUMENT_OUTPUT_CHARS
    ):
        raise DocumentExtractionError("content_document_limit_exceeded")
    return normalized


def _worker_environment() -> dict[str, str]:
    allowed = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP")
    environment = {key: os.environ[key] for key in allowed if os.environ.get(key)}
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def _decode_worker_response(payload: bytes) -> ExtractedDocument:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise DocumentExtractionError("content_document_parser_crashed") from None
    if not isinstance(value, dict) or value.get("ok") is not True:
        code = value.get("code") if isinstance(value, dict) else None
        if code in _SAFE_WORKER_CODES:
            raise DocumentExtractionError(str(code))
        raise DocumentExtractionError("content_document_parser_crashed")
    if set(value) != {"ok", "result"} or not isinstance(value["result"], dict):
        raise DocumentExtractionError("content_document_parser_crashed")
    result = value["result"]
    if set(result) != {"format", "text", "char_count", "truncated", "unit_count"}:
        raise DocumentExtractionError("content_document_parser_crashed")
    try:
        document = ExtractedDocument(**result)
    except TypeError:
        raise DocumentExtractionError("content_document_parser_crashed") from None
    if (
        document.format not in SUPPORTED_DOCUMENT_EXTENSIONS
        or not isinstance(document.text, str)
        or not document.text
        or not isinstance(document.char_count, int)
        or document.char_count != len(document.text)
        or not 1 <= document.char_count <= MAX_DOCUMENT_OUTPUT_CHARS
        or not isinstance(document.truncated, bool)
        or not isinstance(document.unit_count, int)
        or not 1 <= document.unit_count <= max(MAX_PDF_PAGES, MAX_PPTX_SLIDES, 2_000)
    ):
        raise DocumentExtractionError("content_document_parser_crashed")
    return document


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _worker_main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[1] != "--worker":
        return 2
    try:
        max_chars = int(argv[3])
        payload = sys.stdin.buffer.read(MAX_DOCUMENT_INPUT_BYTES + 1)
        result = extract_document_bytes(
            extension=argv[2], payload=payload, max_chars=max_chars
        )
        response: dict[str, Any] = {"ok": True, "result": asdict(result)}
    except DocumentExtractionError as exc:
        response = {"ok": False, "code": exc.code}
    except Exception:  # noqa: BLE001
        response = {"ok": False, "code": "content_document_parser_crashed"}
    encoded = json.dumps(
        response, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(_worker_main(sys.argv))

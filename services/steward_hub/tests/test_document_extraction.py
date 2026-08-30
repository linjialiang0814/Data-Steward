from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from pypdf import PdfWriter

from steward_hub.document_extraction import (
    DocumentExtractionError,
    DocumentExtractorSupervisor,
    extract_document_bytes,
)


def build_docx(*, text: str = "高等数学复习：极限与导数", extra: dict[str, bytes] | None = None) -> bytes:
    files = {
        "[Content_Types].xml": (
            b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            b'<Override PartName="/word/document.xml" '
            b'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            b"</Types>"
        ),
        "word/document.xml": (
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body>"
            "</w:document>"
        ).encode("utf-8"),
    }
    files.update(extra or {})
    return build_zip(files)


def build_pptx() -> bytes:
    return build_zip(
        {
            "[Content_Types].xml": b"<Types/>",
            "ppt/presentation.xml": b'<p:presentation xmlns:p="urn:p"/>',
            "ppt/slides/slide1.xml": (
                '<p:sld xmlns:p="urn:p" xmlns:a="urn:a"><a:t>课程重点</a:t>'
                "<a:t>连续性与导数</a:t></p:sld>"
            ).encode("utf-8"),
            "ppt/notesSlides/notesSlide1.xml": (
                '<p:notes xmlns:p="urn:p" xmlns:a="urn:a"><a:t>课后完成习题</a:t></p:notes>'
            ).encode("utf-8"),
        }
    )


def build_zip(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    return output.getvalue()


def build_text_pdf(text: str = "Review calculus today") -> bytes:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    result = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, value in enumerate(objects, start=1):
        offsets.append(len(result))
        result.extend(f"{index} 0 obj\n".encode("ascii"))
        result.extend(value)
        result.extend(b"\nendobj\n")
    xref = len(result)
    result.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    result.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        result.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    result.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(result)


class DocumentExtractionTests(unittest.TestCase):
    def test_extracts_docx_paragraph_text(self) -> None:
        result = extract_document_bytes(
            extension="docx", payload=build_docx(), max_chars=4_000
        )
        self.assertEqual(result.format, "docx")
        self.assertIn("极限与导数", result.text)
        self.assertEqual(result.unit_count, 1)
        self.assertFalse(result.truncated)

    def test_extracts_pptx_slides_and_notes(self) -> None:
        result = extract_document_bytes(
            extension="pptx", payload=build_pptx(), max_chars=4_000
        )
        self.assertIn("课程重点", result.text)
        self.assertIn("课后完成习题", result.text)
        self.assertEqual(result.unit_count, 1)

    def test_extracts_text_pdf(self) -> None:
        result = extract_document_bytes(
            extension="pdf", payload=build_text_pdf(), max_chars=4_000
        )
        self.assertIn("Review calculus today", result.text)
        self.assertEqual(result.unit_count, 1)

    def test_pdf_encryption_and_embedded_files_fail_closed(self) -> None:
        encrypted = io.BytesIO()
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer.encrypt("fixture-password")
        writer.write(encrypted)
        with self.assertRaisesRegex(
            DocumentExtractionError, "content_document_encrypted"
        ):
            extract_document_bytes(
                extension="pdf", payload=encrypted.getvalue(), max_chars=100
            )

        embedded = io.BytesIO()
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer.add_attachment("fixture.txt", b"safe fixture")
        writer.write(embedded)
        with self.assertRaisesRegex(
            DocumentExtractionError, "content_document_embedded_object"
        ):
            extract_document_bytes(
                extension="pdf", payload=embedded.getvalue(), max_chars=100
            )

    def test_zip_traversal_external_macro_and_ratio_fail_closed(self) -> None:
        cases = (
            (
                build_docx(extra={"../escape.xml": b"x"}),
                "content_document_invalid",
            ),
            (
                build_docx(
                    extra={
                        "word/_rels/document.xml.rels": (
                            b'<Relationships><Relationship TargetMode="External" '
                            b'Target="https://invalid.example"/></Relationships>'
                        )
                    }
                ),
                "content_document_external_reference",
            ),
            (
                build_docx(extra={"word/vbaProject.bin": b"macro"}),
                "content_document_embedded_object",
            ),
            (
                build_docx(extra={"word/large.xml": b"0" * 200_000}),
                "content_document_limit_exceeded",
            ),
        )
        for payload, code in cases:
            with self.subTest(code=code):
                with self.assertRaisesRegex(DocumentExtractionError, code):
                    extract_document_bytes(
                        extension="docx", payload=payload, max_chars=100
                    )

        duplicate = io.BytesIO()
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr("[Content_Types].xml", b"<Types/>")
            archive.writestr("word/document.xml", b"<document/>")
            archive.writestr("word/document.xml", b"<document/>")
        with self.assertRaisesRegex(
            DocumentExtractionError, "content_document_invalid"
        ):
            extract_document_bytes(
                extension="docx", payload=duplicate.getvalue(), max_chars=100
            )

    def test_truncates_after_safe_text_normalization(self) -> None:
        result = extract_document_bytes(
            extension="docx",
            payload=build_docx(text="A" * 100),
            max_chars=20,
        )
        self.assertEqual(result.text, "A" * 20)
        self.assertTrue(result.truncated)

    def test_supervisor_round_trip_and_owned_timeout(self) -> None:
        supervisor = DocumentExtractorSupervisor(deadline_seconds=5)
        result = supervisor.extract(
            extension="docx", payload=build_docx(), max_chars=4_000
        )
        self.assertIn("高等数学", result.text)

        with tempfile.TemporaryDirectory() as temp:
            script = Path(temp) / "blocked_worker.py"
            script.write_text("import time; time.sleep(30)\n", encoding="utf-8")
            blocked = DocumentExtractorSupervisor(
                deadline_seconds=0.05,
                python_executable=sys.executable,
                worker_script=script,
            )
            with self.assertRaisesRegex(
                DocumentExtractionError, "content_document_timeout"
            ):
                blocked.extract(
                    extension="docx", payload=build_docx(), max_chars=100
                )

    def test_supervisor_does_not_inherit_provider_secret(self) -> None:
        marker = "S6B-PROVIDER-SECRET-MARKER"
        previous = os.environ.get("DATA_STEWARD_HERMES_API_KEY")
        os.environ["DATA_STEWARD_HERMES_API_KEY"] = marker
        try:
            with tempfile.TemporaryDirectory() as temp:
                script = Path(temp) / "environment_worker.py"
                script.write_text(
                    """
import json, os, sys
sys.stdin.buffer.read()
if os.environ.get('DATA_STEWARD_HERMES_API_KEY'):
    raise SystemExit(9)
print(json.dumps({'ok': True, 'result': {'format': 'docx', 'text': 'safe', 'char_count': 4, 'truncated': False, 'unit_count': 1}}), end='')
""".strip(),
                    encoding="utf-8",
                )
                result = DocumentExtractorSupervisor(
                    deadline_seconds=5,
                    python_executable=sys.executable,
                    worker_script=script,
                ).extract(extension="docx", payload=build_docx(), max_chars=100)
                self.assertEqual("safe", result.text)
        finally:
            if previous is None:
                os.environ.pop("DATA_STEWARD_HERMES_API_KEY", None)
            else:
                os.environ["DATA_STEWARD_HERMES_API_KEY"] = previous


if __name__ == "__main__":
    unittest.main()

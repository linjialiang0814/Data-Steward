"""Create deterministic, non-sensitive S6-B live-gate documents."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

from pypdf import PdfWriter


def _zip(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(2026, 8, 5, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100600 << 16
            archive.writestr(info, files[name])
    return output.getvalue()


def _docx() -> bytes:
    return _zip(
        {
            "[Content_Types].xml": (
                b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                b'<Override PartName="/word/document.xml" '
                b'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                b"</Types>"
            ),
            "word/document.xml": (
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                "<w:body><w:p><w:r><w:t>高等数学讲义：本节复习极限、连续性与导数。</w:t>"
                "</w:r></w:p></w:body></w:document>"
            ).encode("utf-8"),
        }
    )


def _pptx() -> bytes:
    return _zip(
        {
            "[Content_Types].xml": b"<Types/>",
            "ppt/presentation.xml": b'<p:presentation xmlns:p="urn:p"/>',
            "ppt/slides/slide1.xml": (
                '<p:sld xmlns:p="urn:p" xmlns:a="urn:a"><a:t>课堂重点</a:t>'
                "<a:t>比较极限定义与连续条件</a:t></p:sld>"
            ).encode("utf-8"),
            "ppt/notesSlides/notesSlide1.xml": (
                '<p:notes xmlns:p="urn:p" xmlns:a="urn:a">'
                "<a:t>课后完成三道导数练习</a:t></p:notes>"
            ).encode("utf-8"),
        }
    )


def _text_pdf() -> bytes:
    text = "Review limits continuity and derivatives"
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    result = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, value in enumerate(objects, start=1):
        offsets.append(len(result))
        result.extend(f"{index} 0 obj\n".encode())
        result.extend(value + b"\nendobj\n")
    xref = len(result)
    result.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    result.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        result.extend(f"{offset:010d} 00000 n \n".encode())
    result.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(result)


def _encrypted_pdf() -> bytes:
    output = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer.encrypt("s6b-fixture-only")
    writer.write(output)
    return output.getvalue()


def _write_new(root: Path, files: dict[str, bytes]) -> dict[str, str]:
    if root.exists() and any(root.iterdir()):
        raise RuntimeError("fixture_target_not_empty")
    root.mkdir(parents=True, exist_ok=True)
    hashes: dict[str, str] = {}
    for name, payload in files.items():
        path = root / name
        path.write_bytes(payload)
        hashes[name] = hashlib.sha256(payload).hexdigest()
    return hashes


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        raise RuntimeError("fixture_root_required")
    parent = Path(argv[1]).resolve()
    positive = _write_new(
        parent / "s6b-multiformat",
        {
            "课程安排.txt": "本周复习极限、连续和导数。".encode(),
            "课堂笔记.md": "# 今日课堂\n重点核对极限定义，并完成课后习题。".encode(),
            "课程讲义.docx": _docx(),
            "复习课件.pptx": _pptx(),
            "作业说明.pdf": _text_pdf(),
        },
    )
    negative = _write_new(
        parent / "s6b-negative",
        {"加密资料-应拒绝.pdf": _encrypted_pdf()},
    )
    print(
        json.dumps(
            {
                "negative_count": len(negative),
                "negative_manifest_sha256": hashlib.sha256(
                    json.dumps(negative, sort_keys=True).encode()
                ).hexdigest(),
                "positive_count": len(positive),
                "positive_manifest_sha256": hashlib.sha256(
                    json.dumps(positive, sort_keys=True).encode()
                ).hexdigest(),
                "status": "PASS",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

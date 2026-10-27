"""
Best-effort text extraction from uploaded documents, so their *content*
(not just filename/description) is searchable via /api/search.

Supports plain text/code/config, PDF, modern Word (.docx) and Excel
(.xlsx/.xlsm). Anything else — or any parse failure — returns "" rather
than raising: extraction is an enrichment, never a reason an upload fails.
Output is capped so a huge document can't bloat the row or the search
index.
"""
from __future__ import annotations

import io
import logging

logger = logging.getLogger("text_extract")

MAX_CHARS = 200_000  # ~200 KB of text per document is plenty for search

_TEXT_EXT = {
    "txt", "log", "md", "markdown", "json", "xml", "yaml", "yml", "csv", "tsv",
    "conf", "cnf", "cfg", "ini", "env", "toml", "properties",
    "sh", "bash", "zsh", "ps1", "py", "js", "ts", "jsx", "tsx",
    "go", "rs", "java", "c", "cpp", "h", "hpp", "rb", "php", "sql",
    "html", "htm", "css", "kt", "swift", "pl", "lua", "r",
}


def _ext(filename: str) -> str:
    if not filename or "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()


def _cap(text: str) -> str:
    text = " ".join(text.split())  # collapse whitespace, drop control noise
    return text[:MAX_CHARS]


def _from_text(data: bytes) -> str:
    return data.decode("utf-8", errors="ignore")


def _from_pdf(data: bytes) -> str:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    out = []
    for page in reader.pages:
        out.append(page.extract_text() or "")
        if sum(len(x) for x in out) > MAX_CHARS:
            break
    return "\n".join(out)


def _from_docx(data: bytes) -> str:
    from docx import Document

    doc = Document(io.BytesIO(data))
    parts = [p.text for p in doc.paragraphs if p.text]
    for table in doc.tables:
        for row in table.rows:
            parts.append(" ".join(c.text for c in row.cells if c.text))
    return "\n".join(parts)


def _from_xls(data: bytes) -> str:
    """Legacy Excel 97-2003 (.xls) via xlrd (pure-python; xlrd 2.x reads
    only the old .xls format, which is exactly what we want here)."""
    import xlrd

    book = xlrd.open_workbook(file_contents=data)
    parts = []
    for sheet in book.sheets():
        parts.append(f"# {sheet.name}")
        for r in range(sheet.nrows):
            cells = [str(c) for c in sheet.row_values(r) if c not in ("", None)]
            if cells:
                parts.append(" ".join(cells))
            if sum(len(x) for x in parts) > MAX_CHARS:
                break
        if sum(len(x) for x in parts) > MAX_CHARS:
            break
    return "\n".join(parts)


def _from_doc(data: bytes) -> str:
    """Legacy Word 97-2003 (.doc, OLE binary) via the `antiword` CLI. The
    binary .doc format has no reliable pure-python reader; antiword is the
    standard extractor. Returns "" if antiword isn't installed or fails."""
    import shutil
    import subprocess
    import tempfile

    if not shutil.which("antiword"):
        return ""
    with tempfile.NamedTemporaryFile(suffix=".doc", delete=True) as tmp:
        tmp.write(data)
        tmp.flush()
        try:
            res = subprocess.run(
                ["antiword", "-w", "0", tmp.name],
                capture_output=True, timeout=20, check=False,
            )
        except Exception:  # noqa: BLE001 — timeout/OS error → no text
            return ""
    return res.stdout.decode("utf-8", errors="ignore") if res.returncode == 0 else ""


def _from_xlsx(data: bytes) -> str:
    from openpyxl import load_workbook

    wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    parts = []
    for ws in wb.worksheets:
        parts.append(f"# {ws.title}")
        for row in ws.iter_rows(values_only=True):
            cells = [str(c) for c in row if c is not None]
            if cells:
                parts.append(" ".join(cells))
            if sum(len(x) for x in parts) > MAX_CHARS:
                break
        if sum(len(x) for x in parts) > MAX_CHARS:
            break
    wb.close()
    return "\n".join(parts)


def extract_text(data: bytes, filename: str = "", content_type: str = "") -> str:
    """Return searchable text for a document, or "" if not extractable.
    Never raises."""
    if not data:
        return ""
    ext = _ext(filename)
    ct = (content_type or "").lower()
    try:
        if ext == "pdf" or ct == "application/pdf":
            return _cap(_from_pdf(data))
        if ext == "docx" or ct == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
            return _cap(_from_docx(data))
        if ext == "doc" or ct == "application/msword":
            return _cap(_from_doc(data))
        if ext in ("xlsx", "xlsm") or ct == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
            return _cap(_from_xlsx(data))
        if ext == "xls" or ct == "application/vnd.ms-excel":
            return _cap(_from_xls(data))
        if ext in _TEXT_EXT or ct.startswith("text/") or ct in ("application/json", "application/xml"):
            return _cap(_from_text(data))
    except Exception as exc:  # noqa: BLE001 — extraction is best-effort
        logger.info("text extraction failed for %s (%s): %s", filename, ct, exc)
    return ""

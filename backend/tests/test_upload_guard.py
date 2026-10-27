"""Upload size guard: Content-Length pre-check + capped read (release 1.0.0 audit)."""

import pytest
from io import BytesIO

from fastapi import UploadFile
from starlette.requests import Request

from app.core.upload_guard import read_upload_capped


def _upload(data: bytes) -> UploadFile:
    return UploadFile(file=BytesIO(data), filename="f.bin", size=len(data))


async def test_rejects_via_content_length_before_read():
    req = Request(scope={"type": "http", "headers": [(b"content-length", str(60 * 1024 * 1024).encode())]})
    with pytest.raises(Exception) as ei:  # noqa: B017
        await read_upload_capped(_upload(b"x"), 50 * 1024 * 1024, req)
    assert getattr(ei.value, "status_code", None) == 413


async def test_capped_read_when_header_lies():
    # no header at all — read is still capped
    req = Request(scope={"type": "http", "headers": []})
    with pytest.raises(Exception) as ei:  # noqa: B017
        await read_upload_capped(_upload(b"y" * 11), 10, req)
    assert getattr(ei.value, "status_code", None) == 413


async def test_small_file_passes():
    req = Request(scope={"type": "http", "headers": [(b"content-length", b"100")]})
    out = await read_upload_capped(_upload(b"hello"), 50 * 1024 * 1024, req)
    assert out == b"hello"


async def test_content_length_slack_avoids_false_positive():
    # multipart overhead: file == limit exactly, header slightly above
    req = Request(scope={"type": "http", "headers": [(b"content-length", str(50 * 1024 * 1024 + 4096).encode())]})
    out = await read_upload_capped(_upload(b"z" * 1024), 50 * 1024 * 1024, req)
    assert out == b"z" * 1024

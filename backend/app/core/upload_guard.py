"""Capped upload reads: reject oversized bodies before buffering them.

The old pattern (`content = await file.read()` then `len(content) > MAX`)
buffers the whole upload in memory first — a lying or absent
Content-Length makes the check useless as protection. Guard order:

1. Content-Length header (cheap, before reading; multipart adds a little
   overhead, hence the slack) — kills the request without touching the body.
2. Capped read (`size = MAX + 1`) — the real guarantee, covers lying or
   missing Content-Length.
3. Length check on what was actually read.
"""

from fastapi import HTTPException, Request, UploadFile

# Multipart boundaries + part headers + tiny fields — Content-Length is a
# few hundred bytes above the file payload; 64 KB slack avoids false 413s.
_CL_SLACK = 64 * 1024


async def read_upload_capped(
    file: UploadFile,
    max_bytes: int,
    request: Request | None = None,
    *,
    what: str = "File",
) -> bytes:
    """Read an upload fully, but never buffer more than *max_bytes*."""
    if request is not None:
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > max_bytes + _CL_SLACK:
            raise HTTPException(413, f"{what} exceeds the {max_bytes // (1024 * 1024)} MB limit")
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(413, f"{what} exceeds the {max_bytes // (1024 * 1024)} MB limit")
    return content

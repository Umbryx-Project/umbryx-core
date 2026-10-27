"""
Abstract evidence storage backend.
Supports local filesystem and S3 (MinIO/AWS) via EVIDENCE_BACKEND env var.
"""

from __future__ import annotations

import os
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import IO


class StorageBackend(ABC):
    """Abstract interface for evidence file storage."""

    @abstractmethod
    async def save(self, project_id: str, filename: str, data: IO[bytes]) -> str:
        """Save a file, return the storage key/path."""

    @abstractmethod
    async def load(self, key: str) -> bytes | None:
        """Load file contents by key. Return None if not found."""

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete a file. Return True if deleted."""

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if a file exists."""

    @abstractmethod
    async def list_files(self, project_id: str, prefix: str = "") -> list[str]:
        """List files for a project, optionally filtered by prefix."""

    @abstractmethod
    async def get_presigned_url(self, key: str, expires: int = 3600) -> str | None:
        """Get a presigned URL for direct download (S3 only). Return None for local."""


class LocalStorageBackend(StorageBackend):
    """Store evidence on local filesystem."""

    def __init__(self):
        default_dir = "/data/evidence"
        if os.environ.get("APP_ENV", "dev").lower() in ("test", "testing"):
            default_dir = os.environ.get(
                "UPLOAD_ROOT",
                os.environ.get("EVIDENCE_LOCAL_DIR", default_dir),
            )
        self.base_dir = Path(os.environ.get("EVIDENCE_LOCAL_DIR", default_dir))
        if os.environ.get("APP_ENV", "dev").lower() not in ("test", "testing"):
            self.base_dir.mkdir(parents=True, exist_ok=True)

    def _resolve(self, key: str) -> Path:
        resolved = (self.base_dir / key).resolve()
        if not str(resolved).startswith(str(self.base_dir.resolve())):
            raise ValueError("Path traversal detected")
        return resolved

    @staticmethod
    def _write_sync(resolved: Path, data: IO[bytes]) -> None:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        with open(resolved, "wb") as f:
            shutil.copyfileobj(data, f)

    async def save(self, project_id: str, filename: str, data: IO[bytes]) -> str:
        file_path = self.base_dir / project_id / filename
        resolved = file_path.resolve()
        if not str(resolved).startswith(str(self.base_dir.resolve())):
            raise ValueError("Path traversal detected")
        # файловый IO — в поток: не блокируем event loop (python:s7493)
        import asyncio

        await asyncio.to_thread(self._write_sync, resolved, data)
        return str(resolved)

    async def load(self, key: str) -> bytes | None:
        # No absolute-path fallback (security audit finding F31): a caller
        # that ever passes a raw, user-influenced key straight through
        # (bypassing the pid-prefixing the current callers do) would
        # otherwise get unrestricted filesystem read access. _resolve()
        # already raises ValueError for anything outside base_dir.
        try:
            path = self._resolve(key)
        except (ValueError, OSError):
            return None
        if path.exists():
            return path.read_bytes()
        return None

    async def delete(self, key: str) -> bool:
        try:
            path = self._resolve(key)
        except ValueError:
            return False
        if path.exists():
            from .secure_delete import secure_delete_file

            secure_delete_file(path)
            return True
        return False

    async def exists(self, key: str) -> bool:
        try:
            return self._resolve(key).exists()
        except ValueError:
            return False

    async def list_files(self, project_id: str, prefix: str = "") -> list[str]:
        dir_path = self.base_dir / project_id
        if not dir_path.exists():
            return []
        result = []
        for f in sorted(dir_path.rglob("*")):
            if f.is_file():
                rel = str(f.relative_to(dir_path))
                if not prefix or rel.startswith(prefix):
                    result.append(f"{project_id}/{rel}")
        return result

    async def get_presigned_url(self, key: str, expires: int = 3600) -> str | None:
        return None


class S3StorageBackend(StorageBackend):
    """Store evidence in S3-compatible storage (AWS S3, MinIO)."""

    def __init__(self):
        try:
            import boto3
        except ImportError:
            raise RuntimeError("boto3 is required for S3 storage: pip install boto3")
        self.endpoint_url = os.environ.get("S3_ENDPOINT_URL")
        self.bucket = os.environ.get("S3_BUCKET", "umbryx-evidence")
        self.region = os.environ.get("S3_REGION", "us-east-1")
        self._client = boto3.client(
            "s3",
            endpoint_url=self.endpoint_url,
            region_name=self.region,
            aws_access_key_id=os.environ.get("S3_ACCESS_KEY"),
            aws_secret_access_key=os.environ.get("S3_SECRET_KEY"),
        )
        try:
            self._client.head_bucket(Bucket=self.bucket)
        except Exception:
            self._client.create_bucket(Bucket=self.bucket)

    async def save(self, project_id: str, filename: str, data: IO[bytes]) -> str:
        key = f"{project_id}/{filename}"
        self._client.upload_fileobj(data, self.bucket, key)
        return key

    async def load(self, key: str) -> bytes | None:
        try:
            resp = self._client.get_object(Bucket=self.bucket, Key=key)
            return resp["Body"].read()
        except Exception:
            return None

    async def delete(self, key: str) -> bool:
        try:
            self._client.delete_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False

    async def exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False

    async def list_files(self, project_id: str, prefix: str = "") -> list[str]:
        resp = self._client.list_objects_v2(Bucket=self.bucket, Prefix=f"{project_id}/{prefix}")
        return [obj["Key"] for obj in resp.get("Contents", [])]

    async def get_presigned_url(self, key: str, expires: int = 3600) -> str | None:
        try:
            return self._client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket, "Key": key},
                ExpiresIn=expires,
            )
        except Exception:
            return None


_backend: StorageBackend | None = None


def get_storage_backend() -> StorageBackend:
    """Return the configured storage backend singleton."""
    global _backend
    if _backend is not None:
        return _backend
    backend_type = os.environ.get("EVIDENCE_BACKEND", "local").lower()
    if backend_type == "s3":
        _backend = S3StorageBackend()
    else:
        _backend = LocalStorageBackend()
    return _backend

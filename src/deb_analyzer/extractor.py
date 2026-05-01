from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
from pathlib import Path
from typing import Any

try:
    import zstandard as zstd
except Exception:  # pragma: no cover
    zstd = None

from .utils import ensure_dir


class DebFormatError(ValueError):
    pass


AR_MAGIC = b"!<arch>\n"


def _parse_ar_members(path: Path) -> dict[str, bytes]:
    data = path.read_bytes()
    if not data.startswith(AR_MAGIC):
        raise DebFormatError("not an ar/deb archive")
    offset = len(AR_MAGIC)
    members: dict[str, bytes] = {}
    while offset + 60 <= len(data):
        header = data[offset : offset + 60]
        offset += 60
        name = header[:16].decode("utf-8", errors="replace").strip()
        size_text = header[48:58].decode("ascii", errors="replace").strip()
        end = header[58:60]
        if end != b"`\n":
            raise DebFormatError("invalid ar header terminator")
        try:
            size = int(size_text)
        except ValueError as exc:
            raise DebFormatError(f"invalid ar member size: {size_text}") from exc
        payload = data[offset : offset + size]
        offset += size + (size % 2)
        clean_name = name.rstrip("/")
        members[clean_name] = payload
    return members


def _decompress(name: str, payload: bytes) -> bytes:
    if name.endswith(".gz"):
        return gzip.decompress(payload)
    if name.endswith(".xz"):
        return lzma.decompress(payload)
    if name.endswith(".bz2"):
        return bz2.decompress(payload)
    if name.endswith(".zst"):
        if zstd is None:
            raise DebFormatError("zstandard support is not installed")
        return zstd.ZstdDecompressor().decompress(payload)
    return payload


def _safe_member_path(target_root: Path, member_name: str) -> Path:
    raw = Path(member_name)
    if raw.is_absolute() or ".." in raw.parts:
        raise DebFormatError(f"unsafe tar path: {member_name}")
    target = (target_root / raw).resolve()
    root = target_root.resolve()
    if root != target and root not in target.parents:
        raise DebFormatError(f"path escapes extraction root: {member_name}")
    return target


def _extract_tar_bytes(name: str, payload: bytes, target: Path, max_file_size: int) -> list[dict[str, Any]]:
    ensure_dir(target)
    tar_data = _decompress(name, payload)
    entries: list[dict[str, Any]] = []
    with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:*") as tar:
        for member in tar.getmembers():
            member_path = _safe_member_path(target, member.name)
            info = {
                "name": member.name,
                "type": "dir" if member.isdir() else "symlink" if member.issym() else "file" if member.isfile() else "other",
                "size": member.size,
                "mode": oct(member.mode),
                "linkname": member.linkname,
            }
            entries.append(info)
            if member.isdir():
                ensure_dir(member_path)
                continue
            if member.issym() or member.islnk():
                info["skipped_reason"] = "links are recorded but not materialized"
                continue
            if not member.isfile():
                continue
            if member.size > max_file_size:
                info["skipped_reason"] = "file exceeds max_file_size"
                continue
            ensure_dir(member_path.parent)
            src = tar.extractfile(member)
            if src is None:
                continue
            member_path.write_bytes(src.read())
            try:
                member_path.chmod(member.mode & 0o7777)
            except OSError:
                pass
    return entries


def extract_deb(deb_path: Path, package_dir: Path, max_file_size_mb: int = 200) -> dict[str, Any]:
    extract_root = ensure_dir(package_dir / "extracted")
    control_dir = ensure_dir(extract_root / "control")
    data_dir = ensure_dir(extract_root / "data")
    members = _parse_ar_members(deb_path)
    required = {"debian-binary"}
    if not required.issubset(members):
        raise DebFormatError("missing debian-binary member")
    control_name = next((name for name in members if name.startswith("control.tar")), None)
    data_name = next((name for name in members if name.startswith("data.tar")), None)
    if not control_name or not data_name:
        raise DebFormatError("missing control.tar.* or data.tar.*")
    max_file_size = max_file_size_mb * 1024 * 1024
    (extract_root / "debian-binary").write_bytes(members["debian-binary"])
    control_entries = _extract_tar_bytes(control_name, members[control_name], control_dir, max_file_size)
    data_entries = _extract_tar_bytes(data_name, members[data_name], data_dir, max_file_size)
    return {
        "debian_binary": members["debian-binary"].decode("utf-8", errors="replace").strip(),
        "members": sorted(members),
        "control_archive": control_name,
        "data_archive": data_name,
        "control_entries": control_entries,
        "data_entries": data_entries,
        "control_dir": str(control_dir),
        "data_dir": str(data_dir),
    }
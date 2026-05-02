from __future__ import annotations

import stat
from pathlib import Path
from typing import Any

from .utils import file_mode_octal, relative_posix, sha256_file


def _risk_tags(rel: str, mode: int, high_risk_paths: list[str]) -> list[str]:
    posix = "/" + rel.replace("\\", "/").lstrip("/")
    tags = []
    is_ios_jailbreak_path = posix.startswith("/var/jb/") or posix == "/var/jb"
    if is_ios_jailbreak_path:
        tags.append("ios_jailbreak_path")
    if any(posix.startswith(prefix.rstrip("/") + "/") or posix == prefix for prefix in high_risk_paths):
        tags.append("high_risk_path")
    if mode & stat.S_ISUID:
        tags.append("suid")
    if mode & stat.S_ISGID:
        tags.append("sgid")
    if mode & 0o002:
        tags.append("ios_jailbreak_world_writable" if is_ios_jailbreak_path else "world_writable")
    if Path(rel).name.startswith("."):
        tags.append("hidden")
    return tags


def analyze_filetree(data_dir: Path, config: dict[str, Any]) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    dirs = 0
    links = 0
    total_size = 0
    high_risk_paths = config.get("paths", {}).get("high_risk", [])
    for path in sorted(data_dir.rglob("*")):
        try:
            st = path.lstat()
        except OSError:
            continue
        rel = relative_posix(path, data_dir)
        entry = {
            "path": rel,
            "mode": file_mode_octal(st.st_mode),
            "size": st.st_size,
            "mtime": int(st.st_mtime),
        }
        if path.is_symlink():
            links += 1
            entry["type"] = "symlink"
            entry["target"] = str(path.readlink())
        elif path.is_dir():
            dirs += 1
            entry["type"] = "dir"
        elif path.is_file():
            total_size += st.st_size
            entry["type"] = "file"
            entry["sha256"] = sha256_file(path)
        else:
            entry["type"] = "other"
        entry["risk_tags"] = _risk_tags(rel, st.st_mode, high_risk_paths)
        files.append(entry)
    return {"root": str(data_dir), "file_count": sum(1 for f in files if f["type"] == "file"), "dir_count": dirs, "link_count": links, "total_size": total_size, "entries": files}
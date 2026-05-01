from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import relative_posix, sha256_file


def hash_tree(root: Path) -> dict[str, Any]:
    files = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        files.append({"path": relative_posix(path, root), "sha256": sha256_file(path), "size": path.stat().st_size})
    return {"root": str(root), "file_count": len(files), "files": files}


def hash_input(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": sha256_file(path), "size": path.stat().st_size, "mtime": int(path.stat().st_mtime)}
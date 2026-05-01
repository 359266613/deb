from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import string
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_name(value: str, fallback: str = "item") -> str:
    value = re.sub(r"[^A-Za-z0-9_.+-]+", "_", value).strip("._")
    return value[:120] or fallback


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, data: Any) -> None:
    ensure_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def file_mode_octal(mode: int) -> str:
    return oct(mode & 0o7777)


def command_output(command: list[str], cwd: Path | None = None, timeout: int = 30) -> dict[str, Any]:
    try:
        proc = subprocess.run(command, cwd=str(cwd) if cwd else None, text=True, capture_output=True, timeout=timeout, check=False)
        return {"ok": proc.returncode == 0, "exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as exc:
        return {"ok": False, "exit_code": None, "stdout": "", "stderr": str(exc)}


def discover_debs(input_path: Path) -> list[Path]:
    if input_path.is_file() and input_path.suffix.lower() == ".deb":
        return [input_path]
    if input_path.is_dir():
        return sorted(p for p in input_path.rglob("*.deb") if p.is_file())
    return []


def printable_strings(data: bytes, min_len: int = 5) -> Iterable[str]:
    allowed = set(bytes(string.printable, "ascii")) - {0x0b, 0x0c}
    buf = bytearray()
    for byte in data:
        if byte in allowed and byte not in {0x0d}:
            buf.append(byte)
        else:
            if len(buf) >= min_len:
                yield buf.decode("utf-8", errors="replace")
            buf.clear()
    if len(buf) >= min_len:
        yield buf.decode("utf-8", errors="replace")


def relative_posix(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def which(name: str) -> str | None:
    return shutil.which(name)
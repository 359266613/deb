from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from .config import load_config
from .extractor import extract_deb
from .filetree import analyze_filetree
from .hashing import hash_input, hash_tree
from .metadata import analyze_metadata
from .utils import ensure_dir, write_json


def _analysis_from_dir(path: Path) -> dict[str, Any]:
    return {
        "metadata": _read_optional(path / "metadata.json"),
        "hashes": _read_optional(path / "hashes.json"),
        "filetree": _read_optional(path / "filetree.json"),
    }


def _read_optional(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    import json

    return json.loads(path.read_text(encoding="utf-8"))


def _quick_analyze_deb(path: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="deb-diff-") as tmp:
        root = Path(tmp)
        pkg_dir = ensure_dir(root / "pkg")
        extracted = extract_deb(path, pkg_dir)
        control_dir = Path(extracted["control_dir"])
        data_dir = Path(extracted["data_dir"])
        config = load_config()
        return {
            "input": hash_input(path),
            "metadata": analyze_metadata(control_dir),
            "filetree": analyze_filetree(data_dir, config),
            "hashes": {"data": hash_tree(data_dir), "control": hash_tree(control_dir)},
        }


def load_target(path: Path) -> dict[str, Any]:
    if path.is_file() and path.suffix.lower() == ".deb":
        return _quick_analyze_deb(path)
    if path.is_dir():
        return _analysis_from_dir(path)
    raise FileNotFoundError(str(path))


def _file_hash_map(target: dict[str, Any]) -> dict[str, str]:
    files = target.get("hashes", {}).get("data", {}).get("files", [])
    return {item["path"]: item["sha256"] for item in files if "path" in item and "sha256" in item}


def _field_diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    old_fields = old.get("metadata", {}).get("fields", {})
    new_fields = new.get("metadata", {}).get("fields", {})
    keys = sorted(set(old_fields) | set(new_fields))
    return {key: {"old": old_fields.get(key), "new": new_fields.get(key)} for key in keys if old_fields.get(key) != new_fields.get(key)}


def diff_targets(old_path: Path, new_path: Path, out_dir: Path) -> dict[str, Any]:
    old = load_target(old_path)
    new = load_target(new_path)
    old_hashes = _file_hash_map(old)
    new_hashes = _file_hash_map(new)
    old_files = set(old_hashes)
    new_files = set(new_hashes)
    added = sorted(new_files - old_files)
    removed = sorted(old_files - new_files)
    changed = sorted(path for path in old_files & new_files if old_hashes[path] != new_hashes[path])
    result = {
        "old": str(old_path),
        "new": str(new_path),
        "metadata_changes": _field_diff(old, new),
        "files": {
            "added": added,
            "removed": removed,
            "changed": changed,
            "added_count": len(added),
            "removed_count": len(removed),
            "changed_count": len(changed),
        },
    }
    result["markdown"] = diff_markdown(result)
    write_json(out_dir / "diff.json", result)
    return result


def diff_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# deb 差异分析",
        "",
        f"- Old: `{result['old']}`",
        f"- New: `{result['new']}`",
        "",
        "## 文件变化",
        "",
        f"- 新增: {result['files']['added_count']}",
        f"- 删除: {result['files']['removed_count']}",
        f"- 修改: {result['files']['changed_count']}",
        "",
        "## 元数据变化",
        "",
    ]
    for key, value in result.get("metadata_changes", {}).items():
        lines.append(f"- `{key}`: `{value['old']}` -> `{value['new']}`")
    lines.extend(["", "## 文件列表预览", ""])
    for group in ["added", "removed", "changed"]:
        items = result["files"].get(group, [])[:50]
        if items:
            lines.append(f"### {group}")
            lines.extend(f"- `{item}`" for item in items)
            lines.append("")
    return "\n".join(lines) + "\n"

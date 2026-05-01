from __future__ import annotations

from pathlib import Path
from typing import Any

from .capabilities import can_use_tool
from .utils import command_output, write_json


def generate_sbom(target_dir: Path, out_path: Path, capabilities: dict[str, Any]) -> dict[str, Any]:
    if not can_use_tool(capabilities, "syft"):
        result = {"status": "skipped", "reason": "syft unavailable"}
        write_json(out_path, result)
        return result
    output = command_output(["syft", str(target_dir), "-o", "spdx-json"], timeout=120)
    if output.get("ok"):
        out_path.write_text(output.get("stdout", ""), encoding="utf-8")
        return {"status": "ok", "path": str(out_path)}
    result = {"status": "error", "stderr": output.get("stderr", "")}
    write_json(out_path, result)
    return result

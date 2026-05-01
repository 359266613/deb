from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import Any

from .utils import command_output, which

TOOLS = ["python", "7z", "tar", "ar", "dpkg-deb", "file", "readelf", "objdump", "strings", "syft"]


def detect_capabilities() -> dict[str, Any]:
    tools: dict[str, Any] = {}
    for tool in TOOLS:
        path = which(tool)
        version = None
        if path:
            cmd = [tool, "--version"] if tool not in {"7z"} else [tool]
            out = command_output(cmd, timeout=5)
            version = (out.get("stdout") or out.get("stderr") or "").splitlines()[:1]
            version = version[0] if version else None
        tools[tool] = {"available": bool(path), "path": path, "version": version}
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "tools": tools,
        "notes": [
            "核心分析不安装 deb，不执行 maintainer scripts。",
            "缺失外部工具时自动降级为 Python 内置分析。",
        ],
    }


def can_use_tool(capabilities: dict[str, Any], tool: str) -> bool:
    return bool(capabilities.get("tools", {}).get(tool, {}).get("available"))
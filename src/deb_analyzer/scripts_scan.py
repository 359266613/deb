from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import sha256_file

SCRIPT_NAMES = ["preinst", "postinst", "prerm", "postrm", "config"]


def scan_scripts(control_dir: Path, config: dict[str, Any]) -> dict[str, Any]:
    rules = config.get("keywords", {}).get("script_keywords", [])
    scripts = []
    findings = []
    for name in SCRIPT_NAMES:
        path = control_dir / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        item = {"name": name, "path": str(path), "sha256": sha256_file(path), "size": path.stat().st_size, "matches": []}
        for rule in rules:
            pattern = str(rule.get("pattern", ""))
            if pattern and pattern.lower() in text.lower():
                match = {"rule_id": rule.get("id", pattern), "pattern": pattern, "severity": rule.get("severity", "medium")}
                item["matches"].append(match)
                findings.append({"type": "maintainer_script", "severity": match["severity"], "path": name, "rule_id": match["rule_id"], "evidence": pattern})
        scripts.append(item)
    return {"scripts": scripts, "findings": findings}
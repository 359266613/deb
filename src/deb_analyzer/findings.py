from __future__ import annotations

from typing import Any


def collect_findings(*sources: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for source in sources:
        findings.extend(source.get("findings", []))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: (order.get(str(x.get("severity", "info")).lower(), 9), x.get("path", ""), x.get("rule_id", "")))
    counts: dict[str, int] = {}
    for finding in findings:
        sev = str(finding.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return {"count": len(findings), "severity_counts": counts, "items": findings}


def filetree_findings(filetree: dict[str, Any]) -> dict[str, Any]:
    items = []
    for entry in filetree.get("entries", []):
        for tag in entry.get("risk_tags", []):
            severity = "high" if tag in {"suid", "sgid", "world_writable"} else "medium"
            items.append({"type": "filetree", "severity": severity, "path": entry.get("path"), "rule_id": tag, "evidence": entry.get("mode")})
    return {"findings": items}
from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import write_json


def write_package_outputs(pkg_dir: Path, outputs: dict[str, Any]) -> None:
    for name, data in outputs.items():
        write_json(pkg_dir / f"{name}.json", data)


def package_report_md(package_id: str, metadata: dict[str, Any], filetree: dict[str, Any], findings: dict[str, Any]) -> str:
    lines = [
        f"# {package_id}",
        "",
        "## 基础信息",
        "",
        f"- Package: `{metadata.get('package') or ''}`",
        f"- Version: `{metadata.get('version') or ''}`",
        f"- Architecture: `{metadata.get('architecture') or ''}`",
        f"- Depends: `{metadata.get('depends') or ''}`",
        "",
        "## 文件统计",
        "",
        f"- 文件数: {filetree.get('file_count', 0)}",
        f"- 目录数: {filetree.get('dir_count', 0)}",
        f"- 软链接数: {filetree.get('link_count', 0)}",
        f"- 总大小: {filetree.get('total_size', 0)} bytes",
        "",
        "## 发现项",
        "",
        f"- 总数: {findings.get('count', 0)}",
    ]
    counts = findings.get("severity_counts", {})
    for severity in ["critical", "high", "medium", "low", "info"]:
        if counts.get(severity):
            lines.append(f"- {severity}: {counts[severity]}")
    lines.extend(["", "## Top Findings", ""])
    for item in findings.get("items", [])[:50]:
        lines.append(f"- `{item.get('severity', 'info')}` `{item.get('rule_id', '')}` `{item.get('path', '')}` - {item.get('evidence', '')}")
    return "\n".join(lines) + "\n"


def run_report_md(summary: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    lines = [
        f"# deb 分析批次 {summary.get('run_id')}",
        "",
        f"- 状态: `{summary.get('status')}`",
        f"- 输入包数量: {summary.get('deb_count', 0)}",
        f"- 成功: {summary.get('ok', 0)}",
        f"- 失败: {summary.get('error', 0)}",
        f"- 输出目录: `{summary.get('run_dir')}`",
        "",
        "## 包列表",
        "",
    ]
    if not rows:
        lines.append("当前为 dry-run 或没有可分析包。")
    for row in rows:
        lines.append(f"- `{row.get('status')}` `{row.get('package_id')}` findings={row.get('finding_count', 0)} files={row.get('file_count', 0)}")
        if row.get("error"):
            lines.append(f"  - error: {row.get('error')}")
    return "\n".join(lines) + "\n"
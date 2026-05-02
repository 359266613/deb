from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import write_json


def write_package_outputs(pkg_dir: Path, outputs: dict[str, Any]) -> None:
    for name, data in outputs.items():
        write_json(pkg_dir / f"{name}.json", data)


def package_report_md(package_id: str, metadata: dict[str, Any], filetree: dict[str, Any], findings: dict[str, Any], binaries: dict[str, Any] | None = None, ios_analysis: dict[str, Any] | None = None) -> str:
    binaries = binaries or {}
    ios_analysis = ios_analysis or {}
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
        "## 二进制统计",
        "",
        f"- Mach-O 数: {binaries.get('macho_count', 0)}",
    ]
    macho_items = [item for item in binaries.get("binaries", []) if item.get("mach_o")]
    if macho_items:
        lines.extend(["", "### Mach-O 摘要", ""])
        for item in macho_items[:20]:
            mach_o = item.get("mach_o", {})
            archs = mach_o.get("architectures") or []
            arch_text = ", ".join(str(arch.get("cpu")) for arch in archs[:8]) if archs else "unknown"
            lines.append(f"- `{item.get('path', '')}` `{item.get('format', '')}` archs={arch_text} size={item.get('size', 0)}")
    lines.extend([
        "",
        "## 发现项",
        "",
        f"- 总数: {findings.get('count', 0)}",
    ])
    counts = findings.get("severity_counts", {})
    for severity in ["critical", "high", "medium", "low", "info"]:
        if counts.get(severity):
            lines.append(f"- {severity}: {counts[severity]}")
    if ios_analysis.get("is_ios_jailbreak_plugin"):
        filters = ios_analysis.get("substrate_filters", {})
        lines.extend([
            "",
            "## iOS 越狱插件专项分析",
            "",
            f"- 授权逻辑初判: {ios_analysis.get('auth_summary', '')}",
            f"- Tweak 注入 Bundles: `{', '.join(filters.get('bundles', [])) or ''}`",
            f"- Tweak 注入 Executables: `{', '.join(filters.get('executables', [])) or ''}`",
            f"- plist 数量: {ios_analysis.get('plist_count', 0)}",
        ])
        urls = ios_analysis.get("external_urls", [])
        if urls:
            lines.extend(["", "### 外部 URL", ""])
            for url in urls[:20]:
                lines.append(f"- `{url}`")
        auth_items = ios_analysis.get("authorization_evidence", [])
        if auth_items:
            lines.extend(["", "### 授权相关证据", ""])
            for item in auth_items[:30]:
                lines.append(f"- `{item.get('source', '')}` `{item.get('kind', '')}` `{item.get('path', '')}` - {item.get('evidence', '')}")
        pref_signals = ios_analysis.get("preference_code_signals", [])
        if pref_signals:
            lines.extend(["", "### 偏好项/设置读写线索", ""])
            for item in pref_signals[:20]:
                lines.append(f"- `{item.get('path', '')}` - {item.get('evidence', '')}")
        hook_signals = ios_analysis.get("hook_signals", [])
        if hook_signals:
            lines.extend(["", "### Hook / Substrate 线索", ""])
            for item in hook_signals[:20]:
                lines.append(f"- `{item.get('path', '')}` - {item.get('evidence', '')}")
        porting = ios_analysis.get("porting_method", {})
        if porting:
            lines.extend(["", "## 可复刻移植方法", ""])
            lines.append(f"- 目标: {porting.get('replication_goal', '')}")
            target_model = porting.get("target_model", [])
            if target_model:
                lines.extend(["", "### 目标模型", ""])
                for item in target_model[:10]:
                    lines.append(f"- {item}")
            core_files = porting.get("core_files", {})
            if core_files:
                lines.extend(["", "### 核心文件", ""])
                for group, paths in core_files.items():
                    if paths:
                        lines.append(f"- {group}: `{', '.join(paths[:12])}`")
            steps = porting.get("steps", [])
            if steps:
                lines.extend(["", "### 复刻步骤", ""])
                for idx, step in enumerate(steps[:12], start=1):
                    lines.append(f"{idx}. {step}")
            blockers = porting.get("blockers", [])
            if blockers:
                lines.extend(["", "### 未确认点", ""])
                for item in blockers[:10]:
                    lines.append(f"- {item}")
            validation = porting.get("validation", [])
            if validation:
                lines.extend(["", "### 验证方法", ""])
                for item in validation[:10]:
                    lines.append(f"- {item}")
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
from __future__ import annotations

import json
import plistlib
import re
from pathlib import Path
from typing import Any, Iterable

from .strings_scan import DOMAIN_RE, URL_RE, _classify_domain_like
from .utils import printable_strings, relative_posix

AUTH_RE = re.compile(
    r"\b(?:authori[sz]e|license|licence|trial|expire|expired|purchase|receipt|subscription|"
    r"buy|pay|paid|verify|server|udid|serial|token|wechat|telegram|github)\b|"
    r"授权|校验|验证|激活|购买|会员|到期|订阅|卡密|设备|联系|微信",
    re.I,
)
STRONG_AUTH_RE = re.compile(
    r"\b(?:authori[sz]e|license|licence|trial|expire|expired|purchase|receipt|subscription|"
    r"buy|pay|paid|server|udid|serial|token)\b|授权|校验|验证|激活|购买|会员|到期|订阅|卡密",
    re.I,
)
DEVICE_FINGERPRINT_RE = re.compile(r"\b(?:device|udid|identifierForVendor|identifier|serial|salt|SecKey|signature|SHA|MD5|base64)\b", re.I)
CRYPTO_VERIFY_RE = re.compile(r"\b(?:SecKey|VerifySignature|signature|publicKey|privateKey|certificate|RSA|ECDSA|SHA256|hash|digest)\b", re.I)
NETWORK_API_RE = re.compile(r"\b(?:NSURL|URLSession|http|https|request|response|JSONSerialization|NSURLConnection|AFNetworking)\b", re.I)
CONTACT_RE = re.compile(r"(?:微信|wechat|telegram|联系|contact|qq|vx|vcr|\bwx\b|\btg\b)[\s:：_-]*[A-Za-z0-9_@.-]{3,40}", re.I)
PREFERENCE_KEY_RE = re.compile(r"(?:defaults|NSUserDefaults|CFPreferences|PSSpecifier|setPreferenceValue|readPreferenceValue)", re.I)
HOOK_RE = re.compile(r"(?:%hook|MSHook|substrate|logos|SpringBoard|MobileSubstrate|PreferenceLoader)", re.I)


def _flatten(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten(child, name)
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            yield from _flatten(child, f"{prefix}[{idx}]")
    else:
        yield prefix, value


def _decode_text_candidates(data: bytes) -> list[str]:
    texts: list[str] = []
    for encoding in ("utf-8", "utf-16-le", "utf-16-be", "gb18030", "latin-1"):
        try:
            text = data.decode(encoding, errors="ignore")
        except Exception:
            continue
        if text:
            texts.append(text)
    return texts


def _unicode_snippets(data: bytes, pattern: re.Pattern[str], limit: int = 80) -> list[str]:
    snippets: list[str] = []
    seen = set()
    for text in _decode_text_candidates(data):
        compact = re.sub(r"[\x00\r\t]+", " ", text)
        for match in pattern.finditer(compact):
            snippet = compact[max(0, match.start() - 100):match.end() + 140].strip()
            snippet = re.sub(r"\s+", " ", snippet)
            if snippet and snippet not in seen:
                seen.add(snippet)
                snippets.append(snippet[:500])
                if len(snippets) >= limit:
                    return snippets
    return snippets


def _strings_for_file(path: Path, min_len: int = 4, limit: int = 20000) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    values = list(printable_strings(data, min_len=min_len))[:limit]
    for snippet in _unicode_snippets(data, AUTH_RE, limit=200):
        if snippet not in values:
            values.append(snippet)
    return values


def _collect_urls_and_domains(texts: Iterable[str]) -> tuple[list[str], list[str]]:
    urls: list[str] = []
    domains: list[str] = []
    seen_urls = set()
    seen_domains = set()
    for text in texts:
        for url in URL_RE.findall(text):
            cleaned = url.strip(".,;:()[]{}<>\"'")
            if cleaned not in seen_urls:
                seen_urls.add(cleaned)
                urls.append(cleaned)
        for domain in DOMAIN_RE.findall(text):
            classified = _classify_domain_like(domain)
            if classified and classified[0] == "domain":
                cleaned = domain.strip(".,;:()[]{}<>\"'")
                if cleaned not in seen_domains:
                    seen_domains.add(cleaned)
                    domains.append(cleaned)
    return urls, domains


def _plist_records(data_dir: Path) -> dict[str, Any]:
    records = []
    filter_bundles: list[str] = []
    filter_executables: list[str] = []
    preference_entries = []
    for path in sorted(data_dir.rglob("*.plist")):
        rel = relative_posix(path, data_dir)
        try:
            obj = plistlib.loads(path.read_bytes())
        except Exception as exc:
            records.append({"path": rel, "parse_error": str(exc)})
            continue
        flat = {key: value for key, value in _flatten(obj)}
        records.append({"path": rel, "keys": sorted(flat.keys())[:200], "object": obj})
        for key, value in flat.items():
            if key.endswith("Filter.Bundles") and isinstance(value, str):
                filter_bundles.append(value)
            if ".Bundles[" in key and isinstance(value, str):
                filter_bundles.append(value)
            if ".Executables[" in key and isinstance(value, str):
                filter_executables.append(value)
        if "PreferenceLoader/Preferences" in rel or rel.endswith("Root.plist") or rel.endswith("Info.plist"):
            preference_entries.append({"path": rel, "object": obj})
    return {
        "plists": records,
        "filter_bundles": sorted(set(filter_bundles)),
        "filter_executables": sorted(set(filter_executables)),
        "preference_entries": preference_entries,
    }


def _classify_auth_evidence(value: str) -> str | None:
    if STRONG_AUTH_RE.search(value):
        return "strong_auth"
    if CONTACT_RE.search(value):
        return "contact"
    if CRYPTO_VERIFY_RE.search(value):
        return "crypto_verify"
    if DEVICE_FINGERPRINT_RE.search(value):
        return "device_fingerprint"
    if NETWORK_API_RE.search(value):
        return "network_api"
    return None


def _clean_evidence(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    anchors = [
        "✅ 已授权", "⚠️ 未授权", "未授权", "设备未授权", "获取许可证", "请输入许可证",
        "复制设备码", "导入许可证", "许可证不能为空", "授权成功", "授权失败", "许可证验证通过",
        "Unique Device ID", "MGCopyAnswer", "ios16dao_device_salt_v2", "微信:VCR66T",
    ]
    positions = [value.find(anchor) for anchor in anchors if value.find(anchor) >= 0]
    if positions:
        start = max(0, min(positions) - 20)
        value = value[start:start + 360]
    return value[:500]


def _evidence_rank(item: dict[str, Any]) -> tuple[int, str, str]:
    kind_order = {
        "strong_auth": 0,
        "device_fingerprint": 1,
        "crypto_verify": 2,
        "contact": 3,
        "network_api": 4,
    }
    source_order = {"metadata": 0, "strings": 1}
    return (
        kind_order.get(str(item.get("kind")), 9),
        str(source_order.get(str(item.get("source")), 9)),
        str(item.get("path", "")),
    )


def _evidence_dedupe_key(item: dict[str, Any]) -> tuple[Any, ...]:
    evidence = str(item.get("evidence", ""))
    auth_ui_markers = (
        "已授权", "未授权", "获取许可证", "请输入许可证", "导入许可证",
        "授权成功", "授权失败", "许可证验证通过",
    )
    if any(marker in evidence for marker in auth_ui_markers):
        return (item.get("source"), item.get("path"), item.get("kind"), "authorization_ui_text")
    if "MGCopyAnswer" in evidence or "Unique Device ID" in evidence or "ios16dao_device_salt_v2" in evidence:
        return (item.get("source"), item.get("path"), item.get("kind"), "device_id_derivation")
    return (item.get("source"), item.get("path"), item.get("kind"), evidence)


def _metadata_texts(metadata: dict[str, Any]) -> list[str]:
    fields = metadata.get("fields", {}) if isinstance(metadata.get("fields"), dict) else {}
    texts = []
    for key, value in fields.items():
        if isinstance(value, str):
            texts.append(f"{key}: {value}")
    return texts


def _porting_method(
    metadata: dict[str, Any],
    plist_info: dict[str, Any],
    macho: list[dict[str, Any]],
    auth_summary: str,
    auth_evidence: list[dict[str, Any]],
    preference_keys: list[dict[str, str]],
    hook_signals: list[dict[str, str]],
) -> dict[str, Any]:
    package = metadata.get("package") or "unknown"
    version = metadata.get("version") or "unknown"
    bundles = plist_info.get("filter_bundles", [])
    executables = plist_info.get("filter_executables", [])
    preference_paths = [item.get("path") for item in plist_info.get("preference_entries", []) if item.get("path")]
    macho_paths = [str(item.get("path")) for item in macho if item.get("path")]
    auth_paths = sorted({str(item.get("path")) for item in auth_evidence if item.get("path")})

    target_model = []
    if bundles:
        target_model.append(f"按 Filter.Bundles 注入目标应用/系统组件：{', '.join(bundles[:12])}")
    if executables:
        target_model.append(f"按 Filter.Executables 注入进程：{', '.join(executables[:12])}")
    if not target_model:
        target_model.append("未发现明确 Substrate Filter，需要从 Mach-O 字符串和 plist 继续确认注入入口。")

    steps = [
        "保留 deb 的 control 元数据、依赖项和 data 目录布局，先复刻安装路径，不先改二进制。",
        "按 MobileSubstrate/DynamicLibraries 下的 dylib 与同名 plist 恢复注入关系。",
        "按 PreferenceBundles 与 PreferenceLoader/Preferences 恢复设置面板、Root.plist 和 Info.plist。",
        "以 Mach-O 文件为核心迁移对象，核对 arm64/arm64e 架构、依赖库、签名和目标 rootless/rootful 路径。",
        "把授权证据路径作为优先反汇编入口，定位设备码生成、许可证读取、验签和失败分支。",
        "移植时先实现偏好项读写和 Hook 入口，再接授权状态，最后处理网络/外链交互。",
    ]
    if auth_evidence:
        steps.append("若目标是功能复刻而不是原样搬运，应重新实现授权状态机：设备指纹输入、许可证存储、验签结果、UI 提示四个边界。")
    if preference_keys:
        steps.append("偏好项读写应以报告中的 NSUserDefaults/CFPreferences/PSSpecifier 线索为键名搜索入口。")
    if hook_signals:
        steps.append("Hook 逻辑应从报告中的 Substrate/Logos/SpringBoard 信号定位被 Hook 类和方法。")

    blockers = []
    if not macho_paths:
        blockers.append("未识别 Mach-O，无法确认真实可执行逻辑入口。")
    if not bundles and not executables:
        blockers.append("未识别 Substrate Filter，注入目标仍不确定。")
    if "需继续反汇编" in auth_summary or "需要结合反汇编" in auth_summary:
        blockers.append("授权分支只有静态字符串证据，尚未确认具体控制流。")

    return {
        "package": package,
        "version": version,
        "replication_goal": "复刻 iOS 越狱插件的安装布局、注入目标、设置面板、Mach-O 核心逻辑和授权状态机。",
        "target_model": target_model,
        "core_files": {
            "mach_o": macho_paths[:50],
            "preferences": preference_paths[:50],
            "authorization_evidence_paths": auth_paths[:50],
        },
        "steps": steps,
        "blockers": blockers,
        "validation": [
            "安装后确认 dylib/plist 位于目标越狱环境对应路径。",
            "重启 SpringBoard 或目标进程后确认注入目标匹配 Filter。",
            "打开设置面板确认 PreferenceBundle 正常加载并能读写配置。",
            "分别验证未授权、授权成功、授权失败、许可证缺失四种状态。",
        ],
    }


def analyze_ios_plugin(data_dir: Path, metadata: dict[str, Any], binaries: dict[str, Any]) -> dict[str, Any]:
    plist_info = _plist_records(data_dir)
    evidence: list[dict[str, Any]] = []
    external_texts: list[str] = []
    preference_keys: list[dict[str, str]] = []
    hook_signals: list[dict[str, str]] = []

    for text in _metadata_texts(metadata):
        external_texts.append(text)
        kind = _classify_auth_evidence(text)
        if kind:
            evidence.append({"source": "metadata", "path": "control", "kind": kind, "evidence": _clean_evidence(text)})
        for match in CONTACT_RE.findall(text):
            evidence.append({"source": "metadata", "path": "control", "kind": "contact", "evidence": _clean_evidence(match)})

    for path in sorted(p for p in data_dir.rglob("*") if p.is_file()):
        rel = relative_posix(path, data_dir)
        strings = _strings_for_file(path)
        external_texts.extend(strings)
        for value in strings:
            kind = _classify_auth_evidence(value)
            if kind:
                evidence.append({"source": "strings", "path": rel, "kind": kind, "evidence": _clean_evidence(value)})
            if PREFERENCE_KEY_RE.search(value):
                preference_keys.append({"path": rel, "evidence": _clean_evidence(value)})
            if HOOK_RE.search(value):
                hook_signals.append({"path": rel, "evidence": _clean_evidence(value)})
            for match in CONTACT_RE.findall(value):
                evidence.append({"source": "strings", "path": rel, "kind": "contact", "evidence": _clean_evidence(match)})

    urls, domains = _collect_urls_and_domains(external_texts)
    macho = []
    for item in binaries.get("binaries", []):
        if item.get("mach_o"):
            macho.append({
                "path": item.get("path"),
                "format": item.get("format"),
                "size": item.get("size"),
                "architectures": item.get("mach_o", {}).get("architectures", []),
            })

    deduped_evidence = []
    seen = set()
    for item in evidence:
        key = _evidence_dedupe_key(item)
        if key in seen:
            continue
        seen.add(key)
        deduped_evidence.append(item)
    deduped_evidence.sort(key=_evidence_rank)

    evidence_counts: dict[str, int] = {}
    for item in deduped_evidence:
        kind = str(item.get("kind", "unknown"))
        evidence_counts[kind] = evidence_counts.get(kind, 0) + 1

    has_control_auth = any(item.get("source") == "metadata" and item.get("kind") == "strong_auth" for item in deduped_evidence)
    has_binary_auth = any(item.get("source") == "strings" and item.get("kind") == "strong_auth" for item in deduped_evidence)
    has_crypto = bool(evidence_counts.get("crypto_verify"))
    has_device = bool(evidence_counts.get("device_fingerprint"))
    has_network = bool(evidence_counts.get("network_api") or urls)
    if has_control_auth and has_crypto and has_device:
        auth_summary = "control 明示授权校验；二进制同时出现设备指纹和加密验签线索，授权逻辑很可能是本地设备标识 + 签名/令牌校验。"
    elif has_control_auth and has_device:
        auth_summary = "control 明示授权校验；二进制出现设备指纹线索，授权逻辑可能绑定设备标识。"
    elif has_control_auth:
        auth_summary = "control 描述明确写有“授权校验联系”信息；当前静态证据未确认完整联网授权分支，需继续反汇编验证。"
    elif has_binary_auth:
        auth_summary = "二进制中存在强授权关键词，需要结合反汇编确认授权分支和失败路径。"
    else:
        auth_summary = "未发现明确授权校验证据；当前只识别到插件注入、偏好项和外链等基础线索。"

    porting_method = _porting_method(
        metadata,
        plist_info,
        macho,
        auth_summary,
        deduped_evidence,
        preference_keys,
        hook_signals,
    )

    return {
        "is_ios_jailbreak_plugin": bool(plist_info["filter_bundles"] or plist_info["filter_executables"] or macho),
        "auth_summary": auth_summary,
        "porting_method": porting_method,
        "authorization_evidence": deduped_evidence[:200],
        "external_urls": urls[:200],
        "external_domains": domains[:200],
        "substrate_filters": {
            "bundles": plist_info["filter_bundles"],
            "executables": plist_info["filter_executables"],
        },
        "preference_entries": plist_info["preference_entries"][:20],
        "preference_code_signals": preference_keys[:100],
        "hook_signals": hook_signals[:100],
        "mach_o": macho,
        "plist_count": len(plist_info["plists"]),
        "plists": plist_info["plists"][:50],
    }
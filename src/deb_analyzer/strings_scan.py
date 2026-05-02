from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .utils import printable_strings, relative_posix

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
TOKEN_RE = re.compile(r"\b(?:token|secret|apikey|api_key|password|passwd|bearer)[A-Za-z0-9_\-:=]{0,80}", re.I)
BUNDLE_ID_RE = re.compile(r"\b(?:[a-z][a-z0-9-]*\.){2,}[a-z][a-z0-9-]*\b", re.I)
PUBLIC_DOMAIN_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int",
    "cn", "hk", "tw", "jp", "kr", "us", "uk", "de", "fr", "ru",
    "io", "me", "cc", "tv", "app", "dev", "xyz", "top", "vip", "pro", "info", "biz",
}
IGNORED_DOMAIN_SUFFIXES = (
    ".framework",
    ".dylib",
    ".plist",
    ".bundle",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".unsigned",
)
IGNORED_DOMAIN_PREFIXES = (
    "subject.",
    "issuer.",
)
BUNDLE_ID_PREFIXES = ("com.", "org.", "net.", "io.", "cn.")


def _is_probable_public_domain(value: str) -> bool:
    parts = value.rsplit(".", 1)
    if len(parts) != 2:
        return False
    name, tld = parts
    if tld not in PUBLIC_DOMAIN_TLDS:
        return False
    # Avoid treating common identifiers such as com.apple or NSBundle names as domains.
    if name in {"com", "org", "net", "io", "cn"}:
        return False
    return True


def _classify_domain_like(value: str) -> tuple[str, str] | None:
    lowered = value.lower().strip(".,;:()[]{}<>\"'")
    if lowered.endswith(IGNORED_DOMAIN_SUFFIXES) or lowered.startswith(IGNORED_DOMAIN_PREFIXES):
        return None
    if BUNDLE_ID_RE.fullmatch(lowered) and lowered.startswith(BUNDLE_ID_PREFIXES):
        return "bundle_id", "low"
    if DOMAIN_RE.fullmatch(lowered) and _is_probable_public_domain(lowered):
        return "domain", "medium"
    return None


def scan_strings(data_dir: Path, config: dict[str, Any]) -> dict[str, Any]:
    analysis = config.get("analysis", {})
    max_size = int(analysis.get("max_string_file_size_mb", 50)) * 1024 * 1024
    min_len = int(analysis.get("min_string_length", 5))
    limit_per_file = int(analysis.get("string_limit_per_file", 2000))
    keyword_rules = config.get("keywords", {}).get("string_keywords", [])
    files: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for path in sorted(p for p in data_dir.rglob("*") if p.is_file()):
        rel = relative_posix(path, data_dir)
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_size:
            files.append({"path": rel, "size": size, "skipped_reason": "file exceeds max_string_file_size"})
            continue
        try:
            strings = list(printable_strings(path.read_bytes(), min_len=min_len))[:limit_per_file]
        except OSError as exc:
            files.append({"path": rel, "error": str(exc)})
            continue
        matches = []
        for value in strings:
            for kind, regex in [("url", URL_RE), ("ip", IP_RE), ("token_like", TOKEN_RE)]:
                for match in regex.findall(value):
                    evidence = match[:300]
                    finding = {"type": kind, "severity": "medium" if kind != "token_like" else "high", "path": rel, "rule_id": kind, "evidence": evidence}
                    findings.append(finding)
                    matches.append(finding)
            for match in DOMAIN_RE.findall(value):
                classified = _classify_domain_like(match)
                if classified is None:
                    continue
                kind, severity = classified
                evidence = match[:300]
                finding = {"type": kind, "severity": severity, "path": rel, "rule_id": kind, "evidence": evidence}
                findings.append(finding)
                matches.append(finding)
            lowered = value.lower()
            for rule in keyword_rules:
                pattern = str(rule.get("pattern", ""))
                if pattern and pattern.lower() in lowered:
                    finding = {"type": "keyword", "severity": rule.get("severity", "medium"), "path": rel, "rule_id": rule.get("id", pattern), "evidence": value[:300]}
                    findings.append(finding)
                    matches.append(finding)
        if matches:
            files.append({"path": rel, "size": size, "string_count": len(strings), "matches": matches[:200]})
    return {"files_with_matches": files, "findings": findings[:5000]}
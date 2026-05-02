from __future__ import annotations

from pathlib import Path
import struct
from typing import Any

from .capabilities import can_use_tool
from .utils import command_output, relative_posix

MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": "mach-o-32-be",
    b"\xce\xfa\xed\xfe": "mach-o-32-le",
    b"\xfe\xed\xfa\xcf": "mach-o-64-be",
    b"\xcf\xfa\xed\xfe": "mach-o-64-le",
    b"\xca\xfe\xba\xbe": "fat-mach-o-be",
    b"\xbe\xba\xfe\xca": "fat-mach-o-le",
}

CPU_TYPES = {
    0x01000007: "x86_64",
    0x0100000C: "arm64",
    0x0200000C: "arm64e",
    7: "i386",
    12: "arm",
}

IOS_PLUGIN_BINARY_PREFIXES = (
    "Library/MobileSubstrate/DynamicLibraries/",
    "var/jb/Library/MobileSubstrate/DynamicLibraries/",
    "Library/PreferenceBundles/",
    "var/jb/Library/PreferenceBundles/",
    "Applications/",
    "var/jb/Applications/",
)


def _magic(path: Path) -> bytes:
    try:
        return path.read_bytes()[:4]
    except OSError:
        return b""


def _macho_type(path: Path) -> str | None:
    return MACHO_MAGICS.get(_magic(path))


def _macho_info(path: Path, macho: str) -> dict[str, Any]:
    try:
        data = path.read_bytes()[:4096]
    except OSError as exc:
        return {"magic": macho, "error": str(exc)}
    info: dict[str, Any] = {"magic": macho}
    if macho.startswith("fat-mach-o") and len(data) >= 8:
        endian = ">" if macho.endswith("be") else "<"
        try:
            nfat = struct.unpack(f"{endian}I", data[4:8])[0]
            archs = []
            for idx in range(min(nfat, 16)):
                start = 8 + idx * 20
                if start + 20 > len(data):
                    break
                cputype, cpusubtype, offset, size, align = struct.unpack(f"{endian}IIIII", data[start:start + 20])
                archs.append({
                    "cputype": cputype,
                    "cpu": CPU_TYPES.get(cputype, hex(cputype)),
                    "cpusubtype": cpusubtype,
                    "offset": offset,
                    "size": size,
                    "align": align,
                })
            info.update({"fat_arch_count": nfat, "architectures": archs})
        except Exception as exc:
            info["error"] = str(exc)
    return info


def _is_ios_plugin_binary_path(rel: str) -> bool:
    return rel.startswith(IOS_PLUGIN_BINARY_PREFIXES) or rel.endswith((".dylib", ".framework", ".bundle"))


def analyze_binaries(data_dir: Path, capabilities: dict[str, Any]) -> dict[str, Any]:
    binaries = []
    findings = []
    for path in sorted(p for p in data_dir.rglob("*") if p.is_file()):
        macho = _macho_type(path)
        if macho is None:
            continue
        rel = relative_posix(path, data_dir)
        item: dict[str, Any] = {
            "path": rel,
            "size": path.stat().st_size,
            "format": macho,
            "mach_o": _macho_info(path, macho),
        }
        if can_use_tool(capabilities, "file"):
            item["file"] = command_output(["file", str(path)], timeout=10).get("stdout", "").strip()
        binaries.append(item)
        if _is_ios_plugin_binary_path(rel):
            findings.append({
                "type": "ios_macho_binary",
                "severity": "info",
                "path": rel,
                "rule_id": "ios_plugin_macho",
                "evidence": f"{item['format']} Mach-O in jailbreak plugin path",
            })
    return {
        "binary_count": len(binaries),
        "macho_count": len(binaries),
        "binaries": binaries,
        "findings": findings,
    }

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from elftools.elf.elffile import ELFFile
except Exception:  # pragma: no cover
    ELFFile = None

from .capabilities import can_use_tool
from .utils import command_output, relative_posix

ELF_MAGIC = b"\x7fELF"


def _is_elf(path: Path) -> bool:
    try:
        return path.read_bytes()[:4] == ELF_MAGIC
    except OSError:
        return False


def _pyelftools_info(path: Path) -> dict[str, Any]:
    if ELFFile is None:
        return {"parser": "none", "error": "pyelftools unavailable"}
    try:
        with path.open("rb") as fh:
            elf = ELFFile(fh)
            dynamic_needed = []
            dyn = elf.get_section_by_name(".dynamic")
            if dyn is not None:
                for tag in dyn.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        dynamic_needed.append(tag.needed)
            return {
                "parser": "pyelftools",
                "elf_class": elf.elfclass,
                "endianness": elf.little_endian and "little" or "big",
                "machine": elf.header.get("e_machine"),
                "entry_point": hex(int(elf.header.get("e_entry", 0))),
                "section_count": elf.num_sections(),
                "needed": dynamic_needed,
            }
    except Exception as exc:
        return {"parser": "pyelftools", "error": str(exc)}


def analyze_binaries(data_dir: Path, capabilities: dict[str, Any]) -> dict[str, Any]:
    binaries = []
    findings = []
    for path in sorted(p for p in data_dir.rglob("*") if p.is_file()):
        if not _is_elf(path):
            continue
        rel = relative_posix(path, data_dir)
        item: dict[str, Any] = {"path": rel, "size": path.stat().st_size, "elf": _pyelftools_info(path)}
        if can_use_tool(capabilities, "file"):
            item["file"] = command_output(["file", str(path)], timeout=10).get("stdout", "").strip()
        if can_use_tool(capabilities, "readelf"):
            out = command_output(["readelf", "-d", str(path)], timeout=15)
            item["readelf_dynamic_preview"] = out.get("stdout", "").splitlines()[:80]
        binaries.append(item)
        if rel.startswith(("bin/", "sbin/", "usr/bin/", "usr/sbin/")):
            findings.append({"type": "executable_elf", "severity": "medium", "path": rel, "rule_id": "elf_executable_path", "evidence": "ELF executable in executable path"})
    return {"elf_count": len(binaries), "binaries": binaries, "findings": findings}
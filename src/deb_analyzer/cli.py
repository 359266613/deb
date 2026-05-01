from __future__ import annotations

import argparse
import csv
import traceback
from pathlib import Path
from typing import Any

from .binaries import analyze_binaries
from .capabilities import detect_capabilities
from .config import load_config
from .diffing import diff_targets
from .extractor import DebFormatError, extract_deb
from .filetree import analyze_filetree
from .findings import collect_findings, filetree_findings
from .hashing import hash_input, hash_tree
from .metadata import analyze_metadata
from .reporting import package_report_md, run_report_md, write_package_outputs
from .scripts_scan import scan_scripts
from .strings_scan import scan_strings
from .utils import discover_debs, ensure_dir, safe_name, utc_now, write_json


def make_run_id() -> str:
    return utc_now().replace(":", "").replace("-", "").replace("+00:00", "Z")


def package_id(input_info: dict[str, Any], metadata: dict[str, Any] | None = None) -> str:
    if metadata and metadata.get("package"):
        base = f"{metadata.get('package')}_{metadata.get('version') or 'unknown'}_{input_info['sha256'][:12]}"
    else:
        base = f"{Path(input_info['path']).stem}_{input_info['sha256'][:12]}"
    return safe_name(base, "package")


def analyze_one(deb_path: Path, run_dir: Path, config: dict[str, Any], capabilities: dict[str, Any]) -> dict[str, Any]:
    started = utc_now()
    input_info = hash_input(deb_path)
    pkg_id = package_id(input_info)
    pkg_dir = ensure_dir(run_dir / "packages" / pkg_id)
    stages: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "package_id": pkg_id,
        "input": input_info,
        "status": "running",
        "started_at": started,
    }
    try:
        extracted = extract_deb(deb_path, pkg_dir, int(config.get("analysis", {}).get("max_file_size_mb", 200)))
        stages.append({"stage": "extract", "status": "ok"})
        control_dir = Path(extracted["control_dir"])
        data_dir = Path(extracted["data_dir"])
        metadata = analyze_metadata(control_dir)
        result["package_id"] = package_id(input_info, metadata)
        if result["package_id"] != pkg_id:
            new_dir = run_dir / "packages" / result["package_id"]
            if new_dir != pkg_dir:
                pkg_dir.rename(new_dir)
                pkg_dir = new_dir
        filetree = analyze_filetree(data_dir, config)
        scripts = scan_scripts(control_dir, config)
        strings = scan_strings(data_dir, config)
        binaries = analyze_binaries(data_dir, capabilities)
        hashes = {"control": hash_tree(control_dir), "data": hash_tree(data_dir)}
        findings = collect_findings(filetree_findings(filetree), scripts, strings, binaries)
        artifacts = {"extracted": extracted, "report": str(pkg_dir / "report.md")}
        write_package_outputs(pkg_dir, {
            "input": input_info,
            "stages": stages,
            "metadata": metadata,
            "filetree": filetree,
            "scripts": scripts,
            "strings": strings,
            "binaries": binaries,
            "hashes": hashes,
            "findings": findings,
            "artifacts": artifacts,
        })
        (pkg_dir / "report.md").write_text(package_report_md(result["package_id"], metadata, filetree, findings), encoding="utf-8")
        result.update({
            "status": "ok",
            "package": metadata.get("package"),
            "version": metadata.get("version"),
            "architecture": metadata.get("architecture"),
            "file_count": filetree.get("file_count", 0),
            "elf_count": binaries.get("elf_count", 0),
            "finding_count": findings.get("count", 0),
            "artifact_dir": str(pkg_dir),
        })
    except Exception as exc:
        result.update({"status": "error", "error_code": type(exc).__name__, "error": str(exc), "traceback": traceback.format_exc()})
        write_json(pkg_dir / "input.json", input_info)
        write_json(pkg_dir / "stages.json", stages + [{"stage": "analyze", "status": "error", "error": str(exc)}])
        write_json(pkg_dir / "errors.json", result)
    result["ended_at"] = utc_now()
    return result


def write_summary_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    ensure_dir(path.parent)
    fields = ["package_id", "status", "package", "version", "architecture", "file_count", "elf_count", "finding_count", "artifact_dir", "error_code", "error"]
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def command_analyze(args: argparse.Namespace) -> int:
    input_path = Path(args.input).resolve()
    out_dir = ensure_dir(Path(args.out).resolve())
    config = load_config(Path(args.config).resolve() if args.config else None, Path(args.keywords).resolve() if args.keywords else None)
    config.setdefault("analysis", {})["jobs"] = args.jobs
    capabilities = detect_capabilities()
    debs = discover_debs(input_path)
    run_id = make_run_id()
    run_dir = ensure_dir(out_dir / run_id)
    manifest = {"run_id": run_id, "started_at": utc_now(), "input": str(input_path), "deb_count": len(debs), "dry_run": args.dry_run, "capabilities": capabilities}
    plan = {"run_id": run_id, "packages": [str(p) for p in debs], "stages": ["extract", "metadata", "filetree", "scripts", "strings", "binaries", "hashes", "findings", "report"]}
    write_json(run_dir / "manifest.json", manifest)
    write_json(run_dir / "plan.json", plan)
    if args.dry_run:
        summary = {"run_id": run_id, "status": "dry_run", "deb_count": len(debs), "run_dir": str(run_dir)}
        write_json(run_dir / "summary.json", summary)
        (run_dir / "report.md").write_text(run_report_md(summary, []), encoding="utf-8")
        print(str(run_dir))
        return 0
    rows = [analyze_one(p, run_dir, config, capabilities) for p in debs]
    ok = sum(1 for r in rows if r.get("status") == "ok")
    summary = {"run_id": run_id, "status": "ok" if ok == len(rows) else "partial", "deb_count": len(debs), "ok": ok, "error": len(rows) - ok, "run_dir": str(run_dir)}
    write_json(run_dir / "summary.json", summary)
    write_summary_csv(run_dir / "summary.csv", rows)
    (run_dir / "report.md").write_text(run_report_md(summary, rows), encoding="utf-8")
    print(str(run_dir))
    return 0 if ok == len(rows) else 1


def command_diff(args: argparse.Namespace) -> int:
    out_dir = ensure_dir(Path(args.out).resolve())
    result = diff_targets(Path(args.old).resolve(), Path(args.new).resolve(), out_dir)
    write_json(out_dir / "diff.json", result)
    (out_dir / "diff.md").write_text(result["markdown"], encoding="utf-8")
    print(str(out_dir))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="deb-analyzer")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze")
    analyze.add_argument("--input", required=True)
    analyze.add_argument("--out", default="outputs")
    analyze.add_argument("--jobs", type=int, default=1)
    analyze.add_argument("--dry-run", action="store_true")
    analyze.add_argument("--config")
    analyze.add_argument("--keywords")
    analyze.set_defaults(func=command_analyze)
    diff = sub.add_parser("diff")
    diff.add_argument("--old", required=True)
    diff.add_argument("--new", required=True)
    diff.add_argument("--out", default="outputs/diff")
    diff.set_defaults(func=command_diff)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
from __future__ import annotations

from pathlib import Path

from deb_analyzer.cli import main
from deb_analyzer.config import load_config
from deb_analyzer.utils import discover_debs


def test_load_config_has_keywords() -> None:
    config = load_config()
    assert "analysis" in config
    assert "keywords" in config


def test_discover_debs_empty_dir(tmp_path: Path) -> None:
    assert discover_debs(tmp_path) == []


def test_cli_help() -> None:
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0

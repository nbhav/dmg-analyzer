#!/usr/bin/env python3
"""Pipeline entry point: run all analysis modules then produce a summary report."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from collections.abc import Callable

from app import (
    binary_info,
    bundle_structure,
    code_signing,
    endpoints,
    frameworks,
    plist_audit,
    secrets,
    summarize,
)
from utils.log import get_logger, setup

log = get_logger("main")

MODULES: list[tuple[str, Callable[[str, str], None], str]] = [
    ("bundle_structure", bundle_structure.analyze, "00_bundle_structure.json"),
    ("binary_info", binary_info.analyze, "01_binary_info.json"),
    ("code_signing", code_signing.analyze, "02_code_signing.json"),
    ("plist_audit", plist_audit.analyze, "03_plist_audit.json"),
    ("secrets", secrets.analyze, "04_secrets.json"),
    ("endpoints", endpoints.analyze, "05_endpoints.json"),
    ("frameworks", frameworks.analyze, "06_frameworks.json"),
]


def extract_strings(extract_dir: Path, output_dir: Path) -> None:
    """Run strings(1) on all executables and dylibs; write sorted unique output to 07_strings.txt."""
    out = output_dir / "07_strings.txt"
    all_strings: set[str] = set()

    for path in extract_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix != ".dylib" and not os.access(path, os.X_OK):
            continue
        try:
            result = subprocess.run(
                ["strings", "-a", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                all_strings.update(result.stdout.splitlines())
        except subprocess.TimeoutExpired as e:
            log.debug("strings timed out for %s: %s", path.name, e)
        except (FileNotFoundError, OSError) as e:
            log.debug("strings failed for %s: %s", path.name, e)

    with out.open("w") as f:
        for s in sorted(all_strings):
            f.write(s + "\n")
    log.info("strings: %d unique strings → %s", len(all_strings), out.name)


def run_module(
    label: str,
    fn: Callable[[str, str], None],
    extract_dir: str,
    output_path: str,
) -> None:
    """Invoke one analysis module; write an error JSON to output_path on failure."""
    log.info("running %s", label)
    try:
        fn(extract_dir, output_path)
    except Exception as e:
        log.error("%s failed: %s", label, e)
        with Path(output_path).open("w") as f:
            json.dump({"error": "module_failed", "module": label, "detail": str(e)}, f)


def parse_args() -> argparse.Namespace:
    """Build and return the parsed CLI namespace."""
    parser = argparse.ArgumentParser(
        description="Run the full DMG static-analysis pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example:\n"
            "  python src/main.py --dmg-name MyApp.dmg "
            "--extract-dir /tmp/extracted --output-dir /output"
        ),
    )
    parser.add_argument("--dmg-name", required=True, help="Display name of the analysed DMG")
    parser.add_argument(
        "--extract-dir",
        required=True,
        help="Path to the already-extracted DMG contents",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where JSON reports and summary will be written",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable DEBUG-level logging",
    )
    parser.add_argument(
        "--skip-strings",
        action="store_true",
        help="Skip the strings(1) extraction step (faster, no 07_strings.txt)",
    )
    return parser.parse_args()


def main() -> None:
    """Coordinate the full analysis pipeline and exit with a non-zero code on critical failure."""
    args = parse_args()
    setup(debug=args.debug)

    extract_dir = args.extract_dir
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    log.info("dmg=%s extract=%s output=%s", args.dmg_name, extract_dir, output_dir)

    for label, fn, filename in MODULES:
        run_module(label, fn, extract_dir, str(output_dir / filename))

    if not args.skip_strings:
        log.info("running strings extraction")
        extract_strings(Path(extract_dir), output_dir)

    log.info("running summarize")
    try:
        summarize.analyze(args.dmg_name, str(output_dir))
    except Exception as e:
        log.error("summarize failed: %s", e)
        sys.exit(1)

    log.info("pipeline complete — output: %s", output_dir)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import json
import plistlib
import subprocess
import sys
from pathlib import Path
from typing import Any

from utils.log import get_logger, setup

log = get_logger("bundle_structure")


def find_app_root(extract_dir: Path) -> Path | None:
    """Return the first .app bundle directory found under extract_dir."""
    for p in extract_dir.rglob("*.app"):
        if p.is_dir():
            return p
    return None


def file_type(path: Path) -> str:
    """Return the file type string from the `file` command, or 'unknown' on failure."""
    try:
        result = subprocess.run(
            ["file", "-b", str(path)], capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired as e:
        log.debug("file command timed out for %s: %s", path.name, e)
        return "unknown"
    except (FileNotFoundError, OSError) as e:
        log.debug("file command failed for %s: %s", path.name, e)
        return "unknown"


def analyze(extract_dir: str, output_path: str) -> None:
    """Walk the extracted DMG tree and catalogue executables, scripts, frameworks, and auto-update config."""
    setup()
    log.info("starting")
    root = Path(extract_dir)
    app = find_app_root(root)

    if app:
        log.info("app root: %s", app.relative_to(root))
    else:
        log.warning("no .app bundle found")

    executables = []
    scripts = []
    frameworks = []
    helpers = []
    suspicious = []
    auto_update = {}
    app_metadata = {}

    SUSPICIOUS_EXTENSIONS = {".sh", ".py", ".rb", ".pl", ".js", ".mjs"}
    SUSPICIOUS_LOCATIONS = {"LaunchAgents", "LaunchDaemons", "cron"}

    for p in root.rglob("*"):
        if not p.is_file():
            continue

        rel = str(p.relative_to(root))
        size = p.stat().st_size
        ftype = file_type(p)

        entry = {"path": rel, "size": size, "type": ftype}

        if "Mach-O" in ftype or "ELF" in ftype:
            executables.append(entry)

        if p.suffix in SUSPICIOUS_EXTENSIONS:
            scripts.append(entry)

        if ".framework" in rel:
            frameworks.append({"path": rel, "size": size})

        if "/Helpers/" in rel or "/XPCServices/" in rel:
            helpers.append(entry)

        if any(loc in rel for loc in SUSPICIOUS_LOCATIONS):
            suspicious.append({**entry, "reason": "suspicious_location"})

        if "appcast" in p.name.lower() or p.name == "SUFeedURL":
            auto_update["appcast_file"] = rel

    if app:
        candidate = app / "Contents" / "Info.plist"
        if candidate.exists():
            try:
                with candidate.open("rb") as pf:
                    plist = plistlib.load(pf)

                app_metadata = {
                    "bundle_id": plist.get("CFBundleIdentifier", ""),
                    "bundle_name": plist.get("CFBundleName", ""),
                    "version": plist.get("CFBundleShortVersionString", ""),
                    "build": plist.get("CFBundleVersion", ""),
                    "min_os": plist.get("LSMinimumSystemVersion", ""),
                    "sdk": plist.get("DTSDKName", ""),
                    "ui_element": plist.get("LSUIElement", False),
                }

                auto_update = {
                    "enabled": plist.get("SUEnableAutomaticChecks", False),
                    "auto_install": plist.get("SUAutomaticallyUpdate", False),
                    "feed_url": plist.get("SUFeedURL", ""),
                    "check_interval": plist.get("SUScheduledCheckInterval", None),
                }

                log.info(
                    "bundle: %s %s", app_metadata.get("bundle_id"), app_metadata.get("version")
                )
            except (plistlib.InvalidFileException, OSError, KeyError) as e:
                log.warning("Info.plist parse error: %s", e)
                app_metadata["parse_error"] = str(e)

    result: dict[str, Any] = {
        "app_root": str(app.relative_to(root)) if app else None,
        "app_metadata": app_metadata,
        "auto_update": auto_update,
        "executables": executables,
        "scripts": scripts,
        "frameworks": list({f["path"]: f for f in frameworks}.values()),
        "helpers": helpers,
        "suspicious_files": suspicious,
        "total_files": sum(1 for _ in root.rglob("*") if _.is_file()),
    }

    log.info(
        "executables=%d scripts=%d frameworks=%d suspicious=%d",
        len(executables),
        len(scripts),
        len(frameworks),
        len(suspicious),
    )

    with Path(output_path).open("w") as f:
        json.dump(result, f, indent=2)
    log.info("done")


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])

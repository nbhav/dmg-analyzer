#!/usr/bin/env python3
"""
00_bundle_structure.py
Maps the full bundle layout: executables, scripts, helpers,
frameworks, suspicious files, and auto-update config.
"""
import json
import os
import subprocess
import sys
from pathlib import Path


def find_app_root(extract_dir: Path) -> Path | None:
    for p in extract_dir.rglob("*.app"):
        if p.is_dir():
            return p
    return None


def file_type(path: Path) -> str:
    try:
        result = subprocess.run(
            ["file", "-b", str(path)],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


def analyze(extract_dir: str, output_path: str) -> None:
    root = Path(extract_dir)
    app = find_app_root(root)

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

        # Executables (Mach-O or ELF)
        if "Mach-O" in ftype or "ELF" in ftype:
            executables.append(entry)

        # Scripts
        if p.suffix in SUSPICIOUS_EXTENSIONS:
            scripts.append(entry)

        # Frameworks
        if ".framework" in rel:
            frameworks.append({"path": rel, "size": size})

        # Helpers
        if "/Helpers/" in rel or "/XPCServices/" in rel:
            helpers.append(entry)

        # Suspicious locations
        if any(loc in rel for loc in SUSPICIOUS_LOCATIONS):
            suspicious.append({**entry, "reason": "suspicious_location"})

        # Appcast / auto-update
        if "appcast" in p.name.lower() or p.name == "SUFeedURL":
            auto_update["appcast_file"] = rel

    # Parse Info.plist for auto-update keys and metadata
    info_plist = None
    if app:
        candidate = app / "Contents" / "Info.plist"
        if candidate.exists():
            info_plist = candidate

    if info_plist:
        try:
            import plistlib
            with open(info_plist, "rb") as f:
                plist = plistlib.load(f)

            app_metadata = {
                "bundle_id":      plist.get("CFBundleIdentifier", ""),
                "bundle_name":    plist.get("CFBundleName", ""),
                "version":        plist.get("CFBundleShortVersionString", ""),
                "build":          plist.get("CFBundleVersion", ""),
                "min_os":         plist.get("LSMinimumSystemVersion", ""),
                "sdk":            plist.get("DTSDKName", ""),
                "ui_element":     plist.get("LSUIElement", False),
            }

            auto_update = {
                "enabled":        plist.get("SUEnableAutomaticChecks", False),
                "auto_install":   plist.get("SUAutomaticallyUpdate", False),
                "feed_url":       plist.get("SUFeedURL", ""),
                "check_interval": plist.get("SUScheduledCheckInterval", None),
            }
        except Exception as e:
            app_metadata["parse_error"] = str(e)

    result = {
        "app_root":    str(app.relative_to(root)) if app else None,
        "app_metadata": app_metadata,
        "auto_update": auto_update,
        "executables": executables,
        "scripts":     scripts,
        "frameworks":  list({f["path"]: f for f in frameworks}.values()),
        "helpers":     helpers,
        "suspicious_files": suspicious,
        "total_files": sum(1 for _ in root.rglob("*") if _.is_file()),
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])

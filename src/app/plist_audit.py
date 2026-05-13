#!/usr/bin/env python3
import json
import plistlib
import re
import sys
from pathlib import Path
from typing import Any

from utils.log import get_logger, setup

log = get_logger("plist_audit")


PERMISSION_KEYS = [
    "NSMicrophoneUsageDescription",
    "NSCameraUsageDescription",
    "NSScreenCaptureUsageDescription",
    "NSSpeechRecognitionUsageDescription",
    "NSLocationUsageDescription",
    "NSLocationWhenInUseUsageDescription",
    "NSContactsUsageDescription",
    "NSCalendarsUsageDescription",
    "NSPhotoLibraryUsageDescription",
    "NSAppleEventsUsageDescription",
    "NSSystemAdministrationUsageDescription",
    "NSInputMonitoringUsageDescription",
    "NSAccessibilityUsageDescription",
]

SECRET_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "jwt"),
    (re.compile(r"phc_[A-Za-z0-9]{20,}"), "posthog_key"),
    (re.compile(r"GOCSPX-[A-Za-z0-9_-]+"), "google_oauth_secret"),
    (re.compile(r"https://[a-f0-9]+@[a-z0-9.]+sentry\.io/\d+"), "sentry_dsn"),
    (re.compile(r"(?i)(secret|api.?key|token|password)\b"), "generic_sensitive_key"),
]

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+|wss?://[^\s\"'<>]+")


def plist_to_dict(path: Path) -> dict[str, Any] | None:
    """Parse a plist file (binary or XML) and return its contents as a dict, or None on failure."""
    try:
        with path.open("rb") as f:
            return plistlib.load(f)  # type: ignore[no-any-return]
    except (plistlib.InvalidFileException, OSError) as e:
        log.debug("binary plist parse failed for %s, trying text: %s", path.name, e)
        try:
            with path.open(errors="replace") as f:
                content = f.read()
            return plistlib.loads(content.encode())  # type: ignore[no-any-return]
        except (plistlib.InvalidFileException, UnicodeDecodeError, ValueError) as e:
            log.debug("text plist parse failed for %s: %s", path.name, e)
            return None


def flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Recursively flatten a nested dict/list structure into dot-notation keys."""
    items = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            items.update(flatten(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            items.update(flatten(v, f"{prefix}[{i}]"))
    else:
        items[prefix] = obj
    return items


def audit_plist(path: Path, root: Path) -> dict:
    """Extract permissions, hardcoded secrets, and URLs from a single plist file."""
    data = plist_to_dict(path)
    if data is None:
        log.debug("failed to parse: %s", path.relative_to(root))
        return {"path": str(path.relative_to(root)), "error": "parse_failed"}

    flat = flatten(data)
    rel = str(path.relative_to(root))

    permissions = {}
    hardcoded_secrets = []
    urls = []
    raw_keys = {}

    for key, value in flat.items():
        val_str = str(value)

        base_key = key.split(".")[-1]
        if base_key in PERMISSION_KEYS:
            permissions[base_key] = val_str

        for pattern, label in SECRET_PATTERNS:
            if pattern.search(val_str) or pattern.search(key):
                preview = val_str[:60] + "..." if len(val_str) > 60 else val_str
                hardcoded_secrets.append(
                    {
                        "key": key,
                        "type": label,
                        "value_preview": preview,
                    }
                )
                break

        found_urls = URL_PATTERN.findall(val_str)
        urls.extend(found_urls)

        if isinstance(value, str):
            raw_keys[key] = value

    return {
        "path": rel,
        "permissions_requested": permissions,
        "hardcoded_secrets": hardcoded_secrets,
        "urls": list(set(urls)),
        "raw_string_keys": raw_keys,
    }


def analyze(extract_dir: str, output_path: str) -> None:
    """Audit all plist files under extract_dir and write a JSON report to output_path."""
    setup()
    log.info("starting")
    root = Path(extract_dir)
    plists = list(root.rglob("*.plist"))
    log.info("found %d plist files", len(plists))

    results = []
    permissions_summary = {}
    all_secrets = []
    all_urls = []

    for plist_path in plists:
        if not plist_path.is_file():
            continue
        audit = audit_plist(plist_path, root)
        results.append(audit)
        permissions_summary.update(audit.get("permissions_requested", {}))
        all_secrets.extend(audit.get("hardcoded_secrets", []))
        all_urls.extend(audit.get("urls", []))

    if all_secrets:
        log.warning("hardcoded secrets found: %d", len(all_secrets))
    log.info(
        "permissions=%d secrets=%d urls=%d",
        len(permissions_summary),
        len(all_secrets),
        len(set(all_urls)),
    )

    output = {
        "plist_count": len(plists),
        "permissions_summary": permissions_summary,
        "hardcoded_secrets": all_secrets,
        "all_urls": list(set(all_urls)),
        "plists": results,
    }

    with Path(output_path).open("w") as f:
        json.dump(output, f, indent=2)
    log.info("done")


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])

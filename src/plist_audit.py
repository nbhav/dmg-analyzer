#!/usr/bin/env python3
"""
03_plist_audit.py
Audits all plist files in the bundle:
- Info.plist: permissions, URL schemes, hardcoded endpoints/keys
- All other plists: surface embedded config, keys, URLs
"""
import json
import plistlib
import re
import sys
from pathlib import Path


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

# Patterns that suggest hardcoded secrets in plist values
SECRET_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "jwt"),
    (re.compile(r"phc_[A-Za-z0-9]{20,}"), "posthog_key"),
    (re.compile(r"GOCSPX-[A-Za-z0-9_-]+"), "google_oauth_secret"),
    (re.compile(r"https://[a-f0-9]+@[a-z0-9.]+sentry\.io/\d+"), "sentry_dsn"),
    (re.compile(r"(?i)(secret|api.?key|token|password)\b"), "generic_sensitive_key"),
]

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+|wss?://[^\s\"'<>]+")


def plist_to_dict(path: Path) -> dict | None:
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        # Try converting XML plist
        try:
            with open(path, "r", errors="replace") as f:
                content = f.read()
            return plistlib.loads(content.encode())
        except Exception:
            return None


def flatten(obj, prefix="") -> dict:
    """Flatten nested plist into dot-notation dict."""
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
    data = plist_to_dict(path)
    if data is None:
        return {"path": str(path.relative_to(root)), "error": "parse_failed"}

    flat = flatten(data)
    rel = str(path.relative_to(root))

    permissions = {}
    hardcoded_secrets = []
    urls = []
    raw_keys = {}

    for key, value in flat.items():
        val_str = str(value)

        # Permissions
        base_key = key.split(".")[-1]
        if base_key in PERMISSION_KEYS:
            permissions[base_key] = val_str

        # Secret patterns
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(val_str) or pattern.search(key):
                preview = val_str[:60] + "..." if len(val_str) > 60 else val_str
                hardcoded_secrets.append({
                    "key": key,
                    "type": label,
                    "value_preview": preview,
                })
                break

        # URLs
        found_urls = URL_PATTERN.findall(val_str)
        urls.extend(found_urls)

        # All string values for raw inspection
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
    root = Path(extract_dir)
    plists = list(root.rglob("*.plist"))

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

    output = {
        "plist_count": len(plists),
        "permissions_summary": permissions_summary,
        "hardcoded_secrets": all_secrets,
        "all_urls": list(set(all_urls)),
        "plists": results,
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])

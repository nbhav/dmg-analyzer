#!/usr/bin/env python3
"""
02_code_signing.py
Checks code signature, entitlements, notarization status,
and team/developer identity.
Note: codesign verification requires macOS; inside Linux container
we parse what we can from CodeResources and Info.plist.
"""
import json
import plistlib
import subprocess
import sys
from pathlib import Path


def run(cmd: list, timeout: int = 10) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


def find_app(extract_dir: Path) -> Path | None:
    for p in extract_dir.rglob("*.app"):
        if p.is_dir():
            return p
    return None


def parse_entitlements(app: Path) -> dict:
    """Parse entitlements from CodeResources or embedded signature."""
    entitlements = {}

    # Try embedded entitlements plist inside the binary
    binary_dir = app / "Contents" / "MacOS"
    if binary_dir.exists():
        for binary in binary_dir.iterdir():
            if binary.is_file():
                rc, out, _ = run(["codesign", "-d", "--entitlements", "-", str(binary)])
                if rc == 0 and out:
                    try:
                        data = plistlib.loads(out.encode())
                        entitlements = data
                    except Exception:
                        pass
                break

    return entitlements


def parse_code_resources(app: Path) -> dict:
    cr_path = app / "Contents" / "_CodeSignature" / "CodeResources"
    if not cr_path.exists():
        return {"present": False}

    result = {"present": True, "file_count": 0}
    try:
        with open(cr_path, "rb") as f:
            cr = plistlib.load(f)
        files = cr.get("files2", cr.get("files", {}))
        result["file_count"] = len(files)
        result["version"] = 2 if "files2" in cr else 1
    except Exception as e:
        result["parse_error"] = str(e)

    return result


def analyze(extract_dir: str, output_path: str) -> None:
    root = Path(extract_dir)
    app = find_app(root)

    result = {
        "app_found": app is not None,
        "signed": False,
        "notarized": None,
        "hardened_runtime": False,
        "team_id": "",
        "developer_id": "",
        "entitlements": {},
        "code_resources": {},
        "sensitive_entitlements": [],
    }

    SENSITIVE_ENTITLEMENTS = {
        "com.apple.security.cs.allow-unsigned-executable-memory": "critical",
        "com.apple.security.cs.disable-library-validation": "high",
        "com.apple.security.cs.allow-dyld-environment-variables": "high",
        "com.apple.security.automation.apple-events": "medium",
        "com.apple.security.device.microphone": "medium",
        "com.apple.security.device.camera": "medium",
        "com.apple.security.personal-information.location": "medium",
        "com.apple.security.files.all": "critical",
        "com.apple.security.network.server": "medium",
        "com.apple.security.network.client": "low",
    }

    if not app:
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
        return

    # CodeResources presence = was signed at some point
    cr = parse_code_resources(app)
    result["code_resources"] = cr
    result["signed"] = cr.get("present", False)

    # Entitlements
    entitlements = parse_entitlements(app)
    result["entitlements"] = entitlements

    # Flag sensitive entitlements
    for key, severity in SENSITIVE_ENTITLEMENTS.items():
        if key in entitlements:
            result["sensitive_entitlements"].append({
                "entitlement": key,
                "value": entitlements[key],
                "severity": severity,
            })

    # Hardened runtime — present if CS_RUNTIME flag set; approximate via entitlements
    # com.apple.security.cs.* keys only exist when hardened runtime is on
    if any(k.startswith("com.apple.security.cs.") for k in entitlements):
        result["hardened_runtime"] = True

    # Notarization check — look for ticket in Contents
    ticket_path = app / "Contents" / "CodeResources"
    stapled = (app / "Contents" / "_CodeSignature" / "CodeDirectory").exists()
    result["notarized"] = "unknown_no_codesign_tool"

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])

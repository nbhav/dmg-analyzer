#!/usr/bin/env python3
import json
import plistlib
import subprocess
import sys
from pathlib import Path
from typing import Any

from utils.log import get_logger, setup

log = get_logger("code_signing")


def run(cmd: list, timeout: int = 10) -> tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr), returning (-1, '', error) on failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired as e:
        log.debug("command timed out %s: %s", cmd[0], e)
        return -1, "", str(e)
    except (FileNotFoundError, OSError) as e:
        log.debug("command failed %s: %s", cmd[0], e)
        return -1, "", str(e)


def find_app(extract_dir: Path) -> Path | None:
    """Return the first .app bundle directory found under extract_dir."""
    for p in extract_dir.rglob("*.app"):
        if p.is_dir():
            return p
    return None


def parse_entitlements(app: Path) -> dict:
    """Extract entitlements from the main binary's embedded signature via codesign."""
    entitlements = {}

    binary_dir = app / "Contents" / "MacOS"
    if binary_dir.exists():
        for binary in binary_dir.iterdir():
            if binary.is_file():
                rc, out, _ = run(["codesign", "-d", "--entitlements", "-", str(binary)])
                if rc == 0 and out:
                    try:
                        data = plistlib.loads(out.encode())
                        entitlements = data
                    except (plistlib.InvalidFileException, UnicodeDecodeError, ValueError) as e:
                        log.debug("entitlements plist parse error: %s", e)
                break

    return entitlements


def parse_code_resources(app: Path) -> dict:
    """Parse _CodeSignature/CodeResources and return presence, file count, and signature version."""
    cr_path = app / "Contents" / "_CodeSignature" / "CodeResources"
    if not cr_path.exists():
        return {"present": False}

    result: dict[str, Any] = {"present": True, "file_count": 0}
    try:
        with cr_path.open("rb") as f:
            cr = plistlib.load(f)
        files = cr.get("files2", cr.get("files", {}))
        result["file_count"] = len(files)
        result["version"] = 2 if "files2" in cr else 1
    except (plistlib.InvalidFileException, OSError, KeyError) as e:
        log.warning("CodeResources parse error: %s", e)
        result["parse_error"] = str(e)

    return result


def analyze(extract_dir: str, output_path: str) -> None:
    """Check code signature, entitlements, and flag sensitive permissions; write results to output_path."""
    setup()
    log.info("starting")
    root = Path(extract_dir)
    app = find_app(root)

    result: dict[str, Any] = {
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

    out_path = Path(output_path)
    if not app:
        log.warning("no .app bundle found")
        with out_path.open("w") as f:
            json.dump(result, f, indent=2)
        return

    cr = parse_code_resources(app)
    result["code_resources"] = cr
    result["signed"] = cr.get("present", False)
    log.info("signed=%s CodeResources files=%s", result["signed"], cr.get("file_count"))

    entitlements = parse_entitlements(app)
    result["entitlements"] = entitlements

    for key, severity in SENSITIVE_ENTITLEMENTS.items():
        if key in entitlements:
            result["sensitive_entitlements"].append(
                {
                    "entitlement": key,
                    "value": entitlements[key],
                    "severity": severity,
                }
            )

    if result["sensitive_entitlements"]:
        log.warning("sensitive entitlements: %d", len(result["sensitive_entitlements"]))

    if any(k.startswith("com.apple.security.cs.") for k in entitlements):
        result["hardened_runtime"] = True

    result["notarized"] = "unknown_no_codesign_tool"

    with out_path.open("w") as f:
        json.dump(result, f, indent=2)
    log.info("done")


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])

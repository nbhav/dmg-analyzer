#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from utils.log import get_logger, setup

log = get_logger("binary_info")


def run(cmd: list, timeout: int = 10) -> str:
    """Run a subprocess and return stdout, returning an empty string on any failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except subprocess.TimeoutExpired as e:
        log.debug("command timed out %s: %s", cmd[0], e)
        return ""
    except (FileNotFoundError, OSError) as e:
        log.debug("command failed %s: %s", cmd[0], e)
        return ""


def find_main_binary(extract_dir: Path) -> Path | None:
    """Return the first executable found inside a .app/Contents/MacOS directory."""
    for app in extract_dir.rglob("*.app"):
        macos = app / "Contents" / "MacOS"
        if macos.exists():
            for f in macos.iterdir():
                if f.is_file():
                    return f
    return None


def parse_macho(binary: Path) -> dict:
    """Parse Mach-O headers and return architectures, linked libraries, and binary protections."""
    from macholib.mach_o import (
        LC_BUILD_VERSION,
        LC_VERSION_MIN_MACOSX,
        MH_ALLOW_STACK_EXECUTION,
        MH_PIE,
    )
    from macholib.MachO import MachO

    result: dict[str, Any] = {
        "architectures": [],
        "min_os": "",
        "sdk": "",
        "linked_libraries": [],
        "binary_protections": {
            "pie": False,
            "hardened_runtime": False,
            "stack_canaries": False,
            "arc": False,
            "nx_stack": False,
        },
    }

    try:
        m = MachO(str(binary))
        for header in m.headers:
            flags = header.header.flags

            if flags & MH_PIE:
                result["binary_protections"]["pie"] = True

            if not (flags & MH_ALLOW_STACK_EXECUTION):
                result["binary_protections"]["nx_stack"] = True

            for cmd in header.commands:
                if hasattr(cmd[1], "name"):
                    try:
                        name = cmd[2].decode("utf-8").rstrip("\x00")
                        if name and name not in result["linked_libraries"]:
                            result["linked_libraries"].append(name)
                    except (UnicodeDecodeError, AttributeError, IndexError) as e:
                        log.debug("linked lib decode error: %s", e)

                lc = cmd[0]
                if lc.cmd in (LC_VERSION_MIN_MACOSX, LC_BUILD_VERSION):
                    try:
                        ver = cmd[1]
                        if hasattr(ver, "minos"):
                            v = ver.minos
                            result["min_os"] = f"{(v>>16)&0xffff}.{(v>>8)&0xff}.{v&0xff}"
                        if hasattr(ver, "sdk"):
                            v = ver.sdk
                            result["sdk"] = f"{(v>>16)&0xffff}.{(v>>8)&0xff}.{v&0xff}"
                    except (AttributeError, ValueError) as e:
                        log.debug("version field parse error: %s", e)

        file_out = run(["file", str(binary)])
        for arch in ["x86_64", "arm64", "arm64e", "i386"]:
            if arch in file_out and arch not in result["architectures"]:
                result["architectures"].append(arch)

        log.debug("architectures: %s", result["architectures"])

    except (ValueError, OSError, AttributeError) as e:
        log.warning("macho parse error: %s", e)
        result["parse_error"] = str(e)

    nm_out = run(["nm", "-u", str(binary)])
    if "__stack_chk_fail" in nm_out:
        result["binary_protections"]["stack_canaries"] = True

    if "objc_release" in nm_out or "_swift_release" in nm_out:
        result["binary_protections"]["arc"] = True

    codesign_out = run(["codesign", "-dvvv", str(binary)])
    if "runtime" in codesign_out.lower():
        result["binary_protections"]["hardened_runtime"] = True

    log.debug("linked libraries: %d", len(result["linked_libraries"]))
    return result


def analyze(extract_dir: str, output_path: str) -> None:
    """Locate the main binary, parse Mach-O metadata, and write results to output_path."""
    setup()
    log.info("starting")
    root = Path(extract_dir)
    binary = find_main_binary(root)

    out_path = Path(output_path)
    if not binary:
        log.warning("no main binary found in %s", extract_dir)
        with out_path.open("w") as f:
            json.dump({"error": "no_main_binary_found"}, f, indent=2)
        return

    log.info("main binary: %s", binary.relative_to(root))
    result: dict[str, Any] = {"binary_path": str(binary.relative_to(root))}
    result.update(parse_macho(binary))

    with out_path.open("w") as f:
        json.dump(result, f, indent=2)
    log.info("done")


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])

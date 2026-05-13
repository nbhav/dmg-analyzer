#!/usr/bin/env python3
"""
01_binary_info.py
Parses Mach-O headers: architectures, linked libraries,
binary protections (PIE, hardened runtime, stack canaries, ARC).
"""
import json
import os
import subprocess
import sys
from pathlib import Path


def run(cmd: list, timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def find_main_binary(extract_dir: Path) -> Path | None:
    for app in extract_dir.rglob("*.app"):
        macos = app / "Contents" / "MacOS"
        if macos.exists():
            for f in macos.iterdir():
                if f.is_file():
                    return f
    return None


def parse_macho(binary: Path) -> dict:
    from macholib.MachO import MachO
    from macholib.mach_o import (
        MH_PIE, MH_ALLOW_STACK_EXECUTION,
        LC_VERSION_MIN_MACOSX, LC_BUILD_VERSION,
    )

    result = {
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
            arch = header.MH_MAGIC
            flags = header.header.flags

            # PIE
            if flags & MH_PIE:
                result["binary_protections"]["pie"] = True

            # NX stack (no execute)
            if not (flags & MH_ALLOW_STACK_EXECUTION):
                result["binary_protections"]["nx_stack"] = True

            for cmd in header.commands:
                # Linked libraries
                if hasattr(cmd[1], 'name'):
                    try:
                        name = cmd[2].decode("utf-8").rstrip("\x00")
                        if name and name not in result["linked_libraries"]:
                            result["linked_libraries"].append(name)
                    except Exception:
                        pass

                # Min OS / SDK
                lc = cmd[0]
                if lc.cmd in (LC_VERSION_MIN_MACOSX, LC_BUILD_VERSION):
                    try:
                        ver = cmd[1]
                        if hasattr(ver, 'minos'):
                            v = ver.minos
                            result["min_os"] = f"{(v>>16)&0xffff}.{(v>>8)&0xff}.{v&0xff}"
                        if hasattr(ver, 'sdk'):
                            v = ver.sdk
                            result["sdk"] = f"{(v>>16)&0xffff}.{(v>>8)&0xff}.{v&0xff}"
                    except Exception:
                        pass

        # Architectures via `file`
        file_out = run(["file", str(binary)])
        for arch in ["x86_64", "arm64", "arm64e", "i386"]:
            if arch in file_out and arch not in result["architectures"]:
                result["architectures"].append(arch)

    except Exception as e:
        result["parse_error"] = str(e)

    # Stack canaries — check for __stack_chk_fail symbol
    nm_out = run(["nm", "-u", str(binary)])
    if "__stack_chk_fail" in nm_out:
        result["binary_protections"]["stack_canaries"] = True

    # ARC — check for objc_release symbol
    if "objc_release" in nm_out or "_swift_release" in nm_out:
        result["binary_protections"]["arc"] = True

    # Hardened runtime — check entitlements for runtime flag
    codesign_out = run(["codesign", "-dvvv", str(binary)])
    if "runtime" in codesign_out.lower():
        result["binary_protections"]["hardened_runtime"] = True

    return result


def analyze(extract_dir: str, output_path: str) -> None:
    root = Path(extract_dir)
    binary = find_main_binary(root)

    if not binary:
        with open(output_path, "w") as f:
            json.dump({"error": "no_main_binary_found"}, f, indent=2)
        return

    result = {"binary_path": str(binary.relative_to(root))}
    result.update(parse_macho(binary))

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])

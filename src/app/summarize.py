#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from typing import Any, cast

from utils.log import get_logger, setup

log = get_logger("summarize")


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def load(path: Path) -> dict[str, Any]:
    """Load a JSON file and return its contents as a dict, or an error dict on failure."""
    try:
        return cast(dict[str, Any], json.loads(path.read_text()))
    except (OSError, json.JSONDecodeError) as e:
        log.warning("failed to load %s: %s", path.name, e)
        return {"error": f"failed_to_load: {path.name}"}


def score_risk(findings: list[dict]) -> int:
    """Return a 0-100 risk score weighted by finding severity."""
    weights = {"critical": 25, "high": 10, "medium": 4, "low": 1}
    total = sum(weights.get(f.get("severity", "low"), 1) for f in findings)
    return min(total, 100)


def analyze(dmg_name: str, output_dir: str) -> None:
    """Aggregate all module JSON reports in output_dir into summary.json and summary.md."""
    setup()
    log.info("starting rollup for %s", dmg_name)
    out = Path(output_dir)

    bundle = load(out / "00_bundle_structure.json")
    binary = load(out / "01_binary_info.json")
    signing = load(out / "02_code_signing.json")
    plists = load(out / "03_plist_audit.json")
    secrets = load(out / "04_secrets.json")
    endpoints = load(out / "05_endpoints.json")
    frameworks = load(out / "06_frameworks.json")

    all_findings = []

    for f in secrets.get("findings", []):
        all_findings.append(
            {
                "source": "secrets",
                "severity": f.get("severity", "medium"),
                "title": f.get("type", "unknown"),
                "detail": f.get("location", "") + " — " + f.get("value_preview", ""),
            }
        )

    for f in plists.get("hardcoded_secrets", []):
        all_findings.append(
            {
                "source": "plist",
                "severity": "high",
                "title": f.get("type", "plist_secret"),
                "detail": f.get("key", "") + " — " + f.get("value_preview", ""),
            }
        )

    for f in signing.get("sensitive_entitlements", []):
        all_findings.append(
            {
                "source": "entitlements",
                "severity": f.get("severity", "medium"),
                "title": f.get("entitlement", ""),
                "detail": str(f.get("value", "")),
            }
        )

    for name in frameworks.get("risk_summary", {}).get("high", []):
        all_findings.append(
            {
                "source": "frameworks",
                "severity": "high",
                "title": f"High-risk SDK: {name}",
                "detail": next(
                    (d["description"] for d in frameworks.get("detected", []) if d["name"] == name),
                    "",
                ),
            }
        )

    au = bundle.get("auto_update", {})
    if au.get("auto_install") and au.get("feed_url"):
        all_findings.append(
            {
                "source": "auto_update",
                "severity": "high",
                "title": "Automatic silent updates enabled",
                "detail": f"Feed: {au['feed_url']}",
            }
        )

    permissions = plists.get("permissions_summary", {})
    for perm, desc in permissions.items():
        all_findings.append(
            {
                "source": "permissions",
                "severity": "medium",
                "title": f"Permission: {perm}",
                "detail": desc,
            }
        )

    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 4))
    risk_score = score_risk(all_findings)

    risk_label = (
        "CRITICAL"
        if risk_score >= 75
        else "HIGH" if risk_score >= 40 else "MEDIUM" if risk_score >= 15 else "LOW"
    )

    summary: dict[str, Any] = {
        "target": {
            "name": dmg_name,
            "bundle_id": bundle.get("app_metadata", {}).get("bundle_id", ""),
            "version": bundle.get("app_metadata", {}).get("version", ""),
            "min_os": bundle.get("app_metadata", {}).get("min_os", ""),
            "sdk": bundle.get("app_metadata", {}).get("sdk", ""),
        },
        "risk_score": risk_score,
        "risk_label": risk_label,
        "findings": {
            "critical": [f for f in all_findings if f["severity"] == "critical"],
            "high": [f for f in all_findings if f["severity"] == "high"],
            "medium": [f for f in all_findings if f["severity"] == "medium"],
            "low": [f for f in all_findings if f["severity"] == "low"],
        },
        "quick_stats": {
            "total_findings": len(all_findings),
            "hardcoded_secrets": secrets.get("total_findings", 0),
            "permissions_requested": len(permissions),
            "tracking_sdks": len(frameworks.get("by_category", {}).get("analytics", [])),
            "crash_sdks": len(frameworks.get("by_category", {}).get("crash", [])),
            "external_endpoints": endpoints.get("summary", {}).get("total_urls", 0),
            "ai_api_endpoints": endpoints.get("summary", {}).get("ai_api_endpoints", 0),
            "auto_update_enabled": au.get("enabled", False),
            "auto_install_enabled": au.get("auto_install", False),
            "signed": signing.get("signed", False),
            "hardened_runtime": signing.get("hardened_runtime", False),
        },
        "network": {
            "tracking_services": endpoints.get("tracking_services", []),
            "ai_apis": endpoints.get("ai_api_endpoints", []),
            "websockets": endpoints.get("websocket_urls", []),
        },
        "binary": {
            "architectures": binary.get("architectures", []),
            "linked_libraries": binary.get("linked_libraries", []),
            "protections": binary.get("binary_protections", {}),
        },
        "report_files": [
            "00_bundle_structure.json",
            "01_binary_info.json",
            "02_code_signing.json",
            "03_plist_audit.json",
            "04_secrets.json",
            "05_endpoints.json",
            "06_frameworks.json",
            "07_strings.txt",
        ],
    }

    with (out / "summary.json").open("w") as f:
        json.dump(summary, f, indent=2)

    md = f"""# DMG Analysis: {dmg_name}

**Risk Score:** {risk_score}/100 — {risk_label}
**Bundle ID:** {summary['target']['bundle_id']}
**Version:** {summary['target']['version']}

## Quick Stats
| Metric | Value |
|--------|-------|
| Hardcoded secrets | {summary['quick_stats']['hardcoded_secrets']} |
| Permissions requested | {summary['quick_stats']['permissions_requested']} |
| Tracking SDKs | {summary['quick_stats']['tracking_sdks']} |
| AI API endpoints | {summary['quick_stats']['ai_api_endpoints']} |
| Auto-update (silent) | {summary['quick_stats']['auto_install_enabled']} |
| Signed | {summary['quick_stats']['signed']} |
| Hardened runtime | {summary['quick_stats']['hardened_runtime']} |

## Critical Findings
{''.join(f"- [{f['source']}] {f['title']}: {f['detail']}\\n" for f in summary['findings']['critical']) or 'None'}

## High Findings
{''.join(f"- [{f['source']}] {f['title']}: {f['detail']}\\n" for f in summary['findings']['high']) or 'None'}

## Medium Findings
{''.join(f"- [{f['source']}] {f['title']}: {f['detail']}\\n" for f in summary['findings']['medium']) or 'None'}
"""
    with (out / "summary.md").open("w") as f:
        f.write(md)

    log.info("risk score: %d/100 (%s)", risk_score, risk_label)
    log.info(
        "critical=%d high=%d medium=%d",
        len(summary["findings"]["critical"]),
        len(summary["findings"]["high"]),
        len(summary["findings"]["medium"]),
    )


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])

#!/usr/bin/env python3
"""
06_frameworks.py
Fingerprints bundled frameworks and SDKs against a known list.
Flags tracking, telemetry, update, and security-relevant SDKs.
"""
import json
import sys
from pathlib import Path


# Known SDK fingerprints: (identifier_string, category, risk, description)
KNOWN_SDKS = [
    # Analytics / Telemetry
    ("PostHog",           "analytics",    "medium", "Product analytics and session recording"),
    ("Amplitude",         "analytics",    "medium", "Behavioral analytics"),
    ("Mixpanel",          "analytics",    "medium", "Event analytics"),
    ("Segment",           "analytics",    "medium", "Data pipeline / analytics router"),
    ("Heap",              "analytics",    "medium", "Retroactive analytics"),
    ("FullStory",         "analytics",    "high",   "Session replay and screen recording"),
    ("LogRocket",         "analytics",    "high",   "Session replay"),
    ("Datadog",           "monitoring",   "low",    "APM and monitoring"),

    # Crash reporting
    ("Sentry",            "crash",        "low",    "Crash reporting and error tracking"),
    ("Crashlytics",       "crash",        "low",    "Firebase crash reporting"),
    ("PLCrashReporter",   "crash",        "low",    "Crash reporting library"),
    ("Bugsnag",           "crash",        "low",    "Crash and error monitoring"),

    # Auto-update
    ("Sparkle",           "update",       "medium", "Auto-update framework — update feed can be hijacked"),

    # Networking
    ("Alamofire",         "networking",   "low",    "HTTP networking library"),
    ("AFNetworking",      "networking",   "low",    "HTTP networking library"),

    # Auth
    ("Auth0",             "auth",         "low",    "Authentication platform"),
    ("Supabase",          "auth",         "low",    "Auth and database backend"),

    # AI / ML
    ("CoreML",            "ai",           "low",    "Apple on-device ML"),
    ("TensorFlow",        "ai",           "low",    "ML framework"),

    # Computer use / accessibility
    ("ScreenCaptureKit",  "screen",       "high",   "Screen capture framework"),
    ("Accessibility",     "access",       "high",   "Accessibility/automation APIs"),

    # Ad / tracking
    ("Google Mobile Ads", "ads",          "high",   "Google advertising SDK"),
    ("Facebook",          "ads",          "high",   "Meta/Facebook SDK"),
    ("AppLovin",          "ads",          "high",   "Ad network"),
    ("IronSource",        "ads",          "high",   "Ad mediation"),
]


def scan_for_sdk(root: Path, identifier: str) -> list[str]:
    """Find files/dirs whose path contains the identifier."""
    matches = []
    for p in root.rglob(f"*{identifier}*"):
        matches.append(str(p.relative_to(root)))
    return matches[:5]  # Cap at 5 matches per SDK to avoid noise


def analyze(extract_dir: str, output_path: str) -> None:
    root = Path(extract_dir)

    detected = []
    by_category: dict[str, list] = {}

    for identifier, category, risk, description in KNOWN_SDKS:
        matches = scan_for_sdk(root, identifier)
        if matches:
            entry = {
                "name":        identifier,
                "category":    category,
                "risk":        risk,
                "description": description,
                "found_at":    matches,
            }
            detected.append(entry)
            by_category.setdefault(category, []).append(entry)

    # Also enumerate .framework directories not in the known list
    all_frameworks = set()
    for p in root.rglob("*.framework"):
        if p.is_dir():
            all_frameworks.add(p.name.replace(".framework", ""))

    known_names = {sdk[0] for sdk in KNOWN_SDKS}
    unknown_frameworks = [
        {"name": f, "category": "unknown", "risk": "unknown"}
        for f in sorted(all_frameworks)
        if f not in known_names
    ]

    result = {
        "detected_count": len(detected),
        "detected": detected,
        "by_category": by_category,
        "unknown_frameworks": unknown_frameworks,
        "risk_summary": {
            "high":   [d["name"] for d in detected if d["risk"] == "high"],
            "medium": [d["name"] for d in detected if d["risk"] == "medium"],
            "low":    [d["name"] for d in detected if d["risk"] == "low"],
        },
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])

#!/usr/bin/env python3
"""Replay IDS/IPS scenarios against the running API to validate decisions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import requests


DEFAULT_SCENARIOS = [
    {
        "event": "web_recon_sweep",
        "severity": "medium",
        "payload": {
            "source": "ids",
            "matched_rules": ["path_traversal_probe"],
            "confidence": 0.64,
            "source_ip": "10.10.10.20",
        },
        "source_ip": "10.10.10.20",
        "expected": {
            "recommendation": "manual_review",
            "promote_event": True,
            "auto_block": False,
        },
    },
    {
        "event": "metasploit_rce_attempt",
        "severity": "critical",
        "payload": {
            "source": "nids",
            "matched_rules": ["rce_pattern", "reverse_shell_signature"],
            "ioc": ["cmd.exe /c"],
            "confidence": 0.93,
            "source_ip": "203.0.113.9",
        },
        "source_ip": "203.0.113.9",
        "expected": {
            "recommendation": "auto_block",
            "promote_event": True,
            "auto_block": True,
        },
    },
    {
        "event": "benign_internal_scan",
        "severity": "low",
        "payload": {
            "source": "network_monitor",
            "matched_rules": ["internal_asset_discovery"],
            "confidence": 0.42,
            "source_ip": "192.168.1.15",
        },
        "source_ip": "192.168.1.15",
        "expected": {
            "recommendation": "monitor_only",
            "promote_event": False,
            "auto_block": False,
        },
    },
]


def load_scenarios(path: str | None) -> list[dict[str, Any]]:
    if not path:
        return DEFAULT_SCENARIOS
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        items = payload.get("scenarios")
        if isinstance(items, list):
            return items
    if isinstance(payload, list):
        return payload
    raise ValueError("Scenario file must contain a list or {'scenarios': [...]} payload")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay IDS/IPS scenarios against SentinelAI")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="API base URL")
    parser.add_argument("--scenario-file", default=None, help="Optional JSON file for custom scenarios")
    parser.add_argument("--output", default=None, help="Optional output JSON file")
    parser.add_argument(
        "--min-accuracy",
        type=float,
        default=0.85,
        help="Minimum expected decision accuracy (0.0-1.0) when scenarios include expected outcomes",
    )
    args = parser.parse_args()

    if args.min_accuracy < 0 or args.min_accuracy > 1:
        print("--min-accuracy must be between 0.0 and 1.0")
        return 2

    scenarios = load_scenarios(args.scenario_file)
    endpoint = f"{args.base_url.rstrip('/')}/api/v1/network/replay/simulate"

    response = requests.post(endpoint, json={"scenarios": scenarios}, timeout=30)
    if response.status_code >= 400:
        print(f"Replay failed: HTTP {response.status_code}")
        print(response.text)
        return 1

    data = response.json()
    print(f"Scenarios: {data.get('total', 0)}")
    for item in data.get("results", []):
        print(
            " - #{scenario} {event} sev={severity} conf={confidence} promote={promote_event} auto_block={auto_block} rec={recommendation}".format(
                **item
            )
        )

    # Evaluate expected outcomes if provided by scenario definitions.
    expected_checks = 0
    matched_checks = 0
    mismatches: list[str] = []
    result_items = data.get("results", [])
    for idx, scenario in enumerate(scenarios):
        if idx >= len(result_items):
            break
        expected = scenario.get("expected") if isinstance(scenario, dict) else None
        if not isinstance(expected, dict):
            continue

        actual = result_items[idx]
        for key in ("recommendation", "promote_event", "auto_block"):
            if key not in expected:
                continue
            expected_checks += 1
            if actual.get(key) == expected.get(key):
                matched_checks += 1
            else:
                mismatches.append(
                    f"Scenario #{idx + 1} ({scenario.get('event', 'unknown')}): {key} expected={expected.get(key)!r} actual={actual.get(key)!r}"
                )

    if expected_checks:
        accuracy = matched_checks / expected_checks
        print(f"Decision accuracy: {matched_checks}/{expected_checks} = {accuracy:.2%}")
        if mismatches:
            print("Mismatches:")
            for line in mismatches:
                print(f" - {line}")
        if accuracy < args.min_accuracy:
            print(
                f"Accuracy gate failed: {accuracy:.2%} < {args.min_accuracy:.2%}. Review IDS/IPS thresholds before release."
            )
            return 3

    if args.output:
        Path(args.output).write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"Saved: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

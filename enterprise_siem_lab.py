#!/usr/bin/env python3
"""
Enterprise SIEM Lab — Wazuh alert triage and dashboard preparation utility.

This utility reads exported Wazuh alerts in JSON or JSON Lines format, normalizes
fields, summarizes alert levels/rules/agents, and writes a dashboard-friendly JSON
summary plus a CSV triage queue. It does not connect to a Wazuh manager, change
cluster configuration, or execute commands on monitored endpoints.

Use only with log data you are authorized to process. Sanitize personal data and
secrets before sharing reports.
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def read_alerts(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8-sig")
    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            # Accept common export wrappers.
            for key in ("alerts", "data", "items", "hits"):
                value = data.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
            return [data]
    except json.JSONDecodeError:
        pass
    alerts = []
    for line_no, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {line_no}: {exc.msg}") from exc
        if isinstance(item, dict):
            alerts.append(item)
    return alerts

def dig(obj: dict, *path: str, default=None):
    cur = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur

def normalize_alert(item: dict, index: int) -> dict:
    # Accept common Wazuh alert structure and simple flat sample structures.
    rule_id = dig(item, "rule", "id", default=item.get("rule_id", "unknown"))
    level = dig(item, "rule", "level", default=item.get("level", 0))
    description = dig(item, "rule", "description", default=item.get("description", "No description"))
    agent_name = dig(item, "agent", "name", default=item.get("agent_name", "unknown"))
    agent_id = dig(item, "agent", "id", default=item.get("agent_id", "unknown"))
    timestamp = item.get("timestamp") or item.get("@timestamp") or item.get("date") or ""
    location = item.get("location", "")
    full_log = item.get("full_log", item.get("message", ""))
    try:
        level_num = int(level)
    except (TypeError, ValueError):
        level_num = 0
    return {
        "event_id": str(item.get("id", item.get("_id", f"event-{index:05d}"))),
        "timestamp": str(timestamp),
        "agent_name": str(agent_name),
        "agent_id": str(agent_id),
        "rule_id": str(rule_id),
        "level": level_num,
        "severity": "critical" if level_num >= 12 else "high" if level_num >= 10 else "medium" if level_num >= 7 else "low" if level_num >= 3 else "info",
        "description": str(description),
        "location": str(location),
        "message": str(full_log)[:1000],
    }

def summarize(alerts: list[dict]) -> dict:
    levels = Counter(str(a["level"]) for a in alerts)
    severities = Counter(a["severity"] for a in alerts)
    rules = Counter((a["rule_id"], a["description"]) for a in alerts)
    agents = Counter((a["agent_id"], a["agent_name"]) for a in alerts)
    top_rules = [
        {"rule_id": rid, "description": desc, "count": count}
        for (rid, desc), count in rules.most_common(10)
    ]
    top_agents = [
        {"agent_id": aid, "agent_name": name, "count": count}
        for (aid, name), count in agents.most_common(10)
    ]
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "severity_counts": dict(sorted(severities.items())),
        "level_counts": dict(sorted(levels.items(), key=lambda pair: int(pair[0]) if pair[0].isdigit() else -1)),
        "top_rules": top_rules,
        "top_agents": top_agents,
        "alerts": alerts,
        "note": "Severity is a convenience mapping from Wazuh rule level; confirm against your organization's triage policy."
    }

def write_csv(path: Path, alerts: list[dict]) -> None:
    fields = ["event_id", "timestamp", "severity", "level", "rule_id", "description",
              "agent_name", "agent_id", "location", "message"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(alerts)

def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize exported Wazuh alerts into JSON and CSV.")
    parser.add_argument("--input", default="sample_wazuh_alerts.json", help="Wazuh JSON export or JSONL file.")
    parser.add_argument("--json-output", default="siem_dashboard_summary.json", help="Dashboard-friendly JSON output.")
    parser.add_argument("--csv-output", default="alert_triage_queue.csv", help="CSV alert triage queue output.")
    parser.add_argument("--min-level", type=int, default=0, help="Only include alerts at or above this Wazuh rule level.")
    args = parser.parse_args()
    if args.min_level < 0:
        parser.error("--min-level must be >= 0")
    try:
        raw_alerts = read_alerts(Path(args.input))
        normalized = [normalize_alert(item, i) for i, item in enumerate(raw_alerts, 1)]
    except (OSError, ValueError) as exc:
        print(f"Error reading input: {exc}", file=sys.stderr)
        return 2
    filtered = [a for a in normalized if a["level"] >= args.min_level]
    summary = summarize(filtered)
    Path(args.json_output).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    write_csv(Path(args.csv_output), filtered)
    print(f"Alerts read: {len(normalized)}")
    print(f"Alerts included (minimum level {args.min_level}): {len(filtered)}")
    print(f"Dashboard summary: {Path(args.json_output).resolve()}")
    print(f"Triage CSV: {Path(args.csv_output).resolve()}")
    print("Note: this script processes exported data; it does not configure or connect to Wazuh.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

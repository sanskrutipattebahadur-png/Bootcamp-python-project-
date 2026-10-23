# Enterprise SIEM Lab — Wazuh Alert Aggregation and Dashboards

An educational companion utility for a Wazuh SIEM lab. It reads **exported** Wazuh alert records in JSON or JSON Lines format, normalizes common fields, summarizes severity/rule/agent counts, and writes a dashboard-friendly JSON summary and CSV triage queue.

> This script processes files only. It does not connect to or deploy a Wazuh cluster, change Wazuh configuration, or execute commands on monitored endpoints.

## Project files

- `enterprise_siem_lab.py` — Python alert-normalization and reporting utility.
- `sample_wazuh_alerts.json` — synthetic sample events for a safe demonstration.
- `requirements.pdf` — hardware, software, functional, and security requirements.
- `project_report.pdf` — project report with the supplied Sandip University logo.
- `sandip_university_logo.png` — supplied logo asset.

## Requirements

- Python 3.10 or newer
- Windows, Linux, or macOS
- No third-party Python packages required
- Optional lab components for the full Wazuh deployment: Wazuh manager/indexer/dashboard, agents for approved Windows/Linux endpoints, and an isolated test network. Install and configure these using the official Wazuh documentation for your chosen version.

## Run the sample

```bash
python enterprise_siem_lab.py --input sample_wazuh_alerts.json
```

Outputs:
- `siem_dashboard_summary.json` — counts, top rules, top agents, and normalized alert records.
- `alert_triage_queue.csv` — spreadsheet-friendly triage queue.

Filter by minimum Wazuh rule level:

```bash
python enterprise_siem_lab.py --input sample_wazuh_alerts.json --min-level 7 --json-output high_priority_summary.json --csv-output high_priority_queue.csv
```

## Wazuh lab workflow

1. Build the Wazuh manager/indexer/dashboard according to official deployment documentation.
2. Enroll only approved lab endpoints and verify that agents report healthy status.
3. Configure appropriate log collection and security monitoring policies.
4. Generate benign, controlled test events in the isolated lab (for example, failed logons using a dedicated test account).
5. Review alerts in the Wazuh dashboard and export records in JSON/JSONL format.
6. Run this utility on the export to create summary data and a CSV triage queue.
7. Tune rules carefully, document false positives, and validate dashboards against the original alert records.

## Input format

The parser supports common Wazuh fields such as `rule.id`, `rule.level`, `rule.description`, `agent.id`, `agent.name`, `timestamp`, `location`, and `full_log`. It also accepts some flat equivalents. Keep exports sanitized before sharing; logs can contain usernames, IP addresses, hostnames, tokens, or other sensitive information.

## Severity mapping

The tool uses a simple convenience mapping: level 12+ critical, 10–11 high, 7–9 medium, 3–6 low, and below 3 info. Adapt this mapping to your organization's policy; Wazuh rule level is not automatically identical to business risk.

## Security and limitations

- Use only data and endpoints you are authorized to monitor.
- Sample records are synthetic and do not represent a real deployment.
- The utility does not deploy Wazuh, configure agents, or automatically create dashboards in Wazuh.
- Do not commit sensitive logs or secrets to GitHub.
- Confirm findings and alert meaning in the original Wazuh event and your incident-response procedures.

## License

Educational project template. Add an appropriate license before redistribution.

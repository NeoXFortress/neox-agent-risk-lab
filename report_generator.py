"""
Report Generator — Produces Agent Exploit Report from execution logs.

Outputs:
- Markdown report (outputs/report.md)
- Static HTML report (outputs/report.html)
- Evidence pack summary

Copyright (c) 2026 Julio Berroa / NeoXFortress LLC
"""

import json
import os
from datetime import datetime, timezone


MITRE_ATLAS = {
    "prompt_injection": {
        "technique_id": "AML.T0051",
        "technique": "LLM Prompt Injection",
        "tactic": "Initial Access / Evasion",
        "description": "Adversary embeds malicious instructions within data processed by an LLM agent, causing it to deviate from intended behavior.",
        "url": "https://atlas.mitre.org/techniques/AML.T0051",
    },
    "exfiltration": {
        "technique_id": "AML.T0048.002",
        "technique": "Exfiltration via AI System",
        "tactic": "Exfiltration",
        "description": "Adversary leverages an AI agent's tool access to exfiltrate sensitive data through approved communication channels.",
        "url": "https://atlas.mitre.org/techniques/AML.T0048",
    },
    "privilege_escalation": {
        "technique_id": "AML.T0044",
        "technique": "Tool/API Abuse",
        "tactic": "Privilege Escalation",
        "description": "Agent attempts to invoke tools or APIs outside its authorized scope, seeking elevated privileges.",
        "url": "https://atlas.mitre.org/techniques/AML.T0044",
    },
}


def load_logs(output_dir):
    log_path = os.path.join(output_dir, "execution-log.json")
    with open(log_path) as f:
        return json.load(f)


def load_receipts(output_dir):
    receipts = {}
    for name in ["prompt_injection", "exfiltration", "privilege_escalation"]:
        path = os.path.join(output_dir, f"receipt-{name}.json")
        if os.path.exists(path):
            with open(path) as f:
                receipts[name] = json.load(f)
    return receipts


def generate_markdown(logs, receipts, output_dir):
    """Generate the Markdown exploit report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# NeoXFortress Agent Exploit Report",
        "",
        f"**Generated:** {now}",
        f"**Lab Version:** 1.0.0",
        f"**Scenarios Executed:** {len(set(l['scenario'] for l in logs))}",
        f"**Total Events:** {len(logs)}",
        f"**Blocked Actions:** {sum(1 for l in logs if l['outcome'] == 'blocked')}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "This report documents three simulated AI agent attack scenarios executed in the",
        "NeoXFortress Agent Risk Lab. Each scenario demonstrates a real-world attack vector",
        "that AI agents face in regulated environments. All attacks were detected and blocked",
        "by the NeoXFortress policy engine.",
        "",
        "| Scenario | MITRE ATLAS | Actions Attempted | Blocked | Risk Score |",
        "|---|---|---|---|---|",
    ]

    for scenario_name in ["prompt_injection", "exfiltration", "privilege_escalation"]:
        scenario_logs = [l for l in logs if l["scenario"] == scenario_name]
        blocked = sum(1 for l in scenario_logs if l["outcome"] == "blocked")
        detected = sum(1 for l in scenario_logs if l["outcome"] == "detected")
        atlas = MITRE_ATLAS.get(scenario_name, {})
        receipt = receipts.get(scenario_name, {})
        risk = receipt.get("compliance", {}).get("risk_score", "N/A")

        lines.append(
            f"| {scenario_name.replace('_', ' ').title()} | "
            f"{atlas.get('technique_id', 'N/A')} | "
            f"{len(scenario_logs)} | {blocked + detected} | {risk}/10 |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## What Happens Without Agent Accountability",
        "",
        "Without a policy engine and receipt system:",
        "",
        "- **Prompt injection** succeeds silently — the agent follows malicious instructions, "
        "exfiltrates data, and no one knows until the breach is discovered.",
        "- **CUI exfiltration** goes undetected — sensitive data reaches Gmail, pastebin, "
        "or adversary-controlled domains with no audit trail.",
        "- **Privilege escalation** enables persistent access — the agent creates backdoor "
        "accounts, disables logging, and modifies firewall rules.",
        "",
        "**With NeoXFortress AAE:** Every attempt is logged, blocked, and produces a signed "
        "receipt that an assessor can verify independently.",
        "",
        "---",
        "",
    ])

    # Detailed scenario sections
    for scenario_name in ["prompt_injection", "exfiltration", "privilege_escalation"]:
        scenario_logs = [l for l in logs if l["scenario"] == scenario_name]
        atlas = MITRE_ATLAS.get(scenario_name, {})
        receipt = receipts.get(scenario_name, {})

        title = scenario_name.replace("_", " ").title()
        lines.extend([
            f"## Scenario: {title}",
            "",
            f"**MITRE ATLAS:** [{atlas.get('technique_id', 'N/A')} — {atlas.get('technique', 'N/A')}]({atlas.get('url', '#')})",
            "",
            f"**Tactic:** {atlas.get('tactic', 'N/A')}",
            "",
            f"**Description:** {atlas.get('description', 'N/A')}",
            "",
            "### Event Log",
            "",
            "| Step | Action | Actor | Decision | Outcome |",
            "|---|---|---|---|---|",
        ])

        for log in scenario_logs:
            lines.append(
                f"| {log['step']} | {log['action']} | {log['actor']} | "
                f"**{log['policy_decision']['decision']}** ({log['policy_decision']['rule_id']}) | "
                f"{log['outcome']} |"
            )

        # Receipt summary
        if receipt:
            comp = receipt.get("compliance", {})
            integrity = receipt.get("integrity", {})
            steps_count = len(receipt.get("execution", {}).get("steps", []))

            lines.extend([
                "",
                "### Agent Accountability Receipt",
                "",
                f"- **Receipt ID:** `{receipt['receipt']['receipt_id']}`",
                f"- **Steps:** {steps_count}",
                f"- **Hash Chain:** {integrity.get('hash_chain', {}).get('alg', 'N/A')} "
                f"({steps_count} links)",
                f"- **Signature:** {integrity.get('signature', {}).get('type', 'N/A')}",
                f"- **Compliance Verdict:** `{comp.get('verdict', 'N/A')}`",
                f"- **Risk Score:** {comp.get('risk_score', 'N/A')}/10",
                f"- **Violated Controls:** {', '.join(comp.get('violated_controls', [])) or 'None'}",
                f"- **Notes:** {comp.get('notes', 'N/A')}",
            ])

        lines.extend(["", "---", ""])

    # CMMC Control Coverage
    all_controls = set()
    for r in receipts.values():
        all_controls.update(r.get("compliance", {}).get("violated_controls", []))

    lines.extend([
        "## CMMC L2 Control Coverage",
        "",
        "Controls exercised across all scenarios:",
        "",
        "| Control ID | Domain | Scenario |",
        "|---|---|---|",
    ])

    control_domains = {
        "SC.L2-3.13.1": "Boundary Protection",
        "SC.L2-3.13.2": "CUI Flow Enforcement",
        "SI.L2-3.14.1": "System Integrity / Flaw Remediation",
        "AC.L2-3.1.1": "Access Control",
        "AC.L2-3.1.2": "Access Control Enforcement",
        "AU.L2-3.3.1": "System Auditing",
    }

    for ctrl in sorted(all_controls):
        # Find which scenarios violated it
        scenarios_using = []
        for name, r in receipts.items():
            if ctrl in r.get("compliance", {}).get("violated_controls", []):
                scenarios_using.append(name.replace("_", " ").title())
        lines.append(
            f"| {ctrl} | {control_domains.get(ctrl, 'Unknown')} | {', '.join(scenarios_using)} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## Evidence Pack Contents",
        "",
        "| File | Description |",
        "|---|---|",
        "| `execution-log.json` | Combined structured event log (all scenarios) |",
        "| `receipt-prompt_injection.json` | Signed receipt — prompt injection scenario |",
        "| `receipt-exfiltration.json` | Signed receipt — exfiltration scenario |",
        "| `receipt-privilege_escalation.json` | Signed receipt — privilege escalation scenario |",
        "| `report.md` | This report (Markdown) |",
        "| `report.html` | This report (HTML) |",
        "",
        "---",
        "",
        f"*Generated by NeoXFortress Agent Risk Lab v1.0.0 — {now}*",
        "",
        "*Copyright (c) 2026 Julio Berroa / NeoXFortress LLC*",
    ])

    md = "\n".join(lines)

    md_path = os.path.join(output_dir, "report.md")
    with open(md_path, "w") as f:
        f.write(md)
    print(f"[*] Markdown report: {md_path}")

    return md


def generate_html(md_content, output_dir):
    """Generate a static HTML report from Markdown content."""
    # Simple Markdown-to-HTML (no dependencies)
    html = md_content

    # Headers
    for i in range(3, 0, -1):
        prefix = "#" * i
        html = "\n".join(
            f"<h{i}>{line[i+1:]}</h{i}>" if line.startswith(prefix + " ") else line
            for line in html.split("\n")
        )

    # Bold
    import re
    html = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", html)

    # Inline code
    html = re.sub(r"`([^`]+)`", r"<code>\1</code>", html)

    # Links
    html = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', html)

    # Tables
    in_table = False
    new_lines = []
    for line in html.split("\n"):
        if "|" in line and line.strip().startswith("|"):
            cells = [c.strip() for c in line.strip().split("|")[1:-1]]
            if all(set(c) <= set("-| ") for c in cells):
                continue  # skip separator row
            if not in_table:
                new_lines.append("<table>")
                tag = "th"
                in_table = True
            else:
                tag = "td"
            row = "".join(f"<{tag}>{c}</{tag}>" for c in cells)
            new_lines.append(f"<tr>{row}</tr>")
        else:
            if in_table:
                new_lines.append("</table>")
                in_table = False
            # Lists
            if line.startswith("- "):
                new_lines.append(f"<li>{line[2:]}</li>")
            elif line.strip() == "---":
                new_lines.append("<hr>")
            elif line.strip() == "":
                new_lines.append("")
            elif not line.startswith("<"):
                new_lines.append(f"<p>{line}</p>")
            else:
                new_lines.append(line)
    if in_table:
        new_lines.append("</table>")

    body = "\n".join(new_lines)

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NeoXFortress Agent Exploit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         max-width: 900px; margin: 40px auto; padding: 0 20px;
         color: #1e293b; line-height: 1.6; }}
  h1 {{ color: #0f1b2d; border-bottom: 3px solid #2563eb; padding-bottom: 8px; }}
  h2 {{ color: #1a2d4a; margin-top: 2em; }}
  h3 {{ color: #334155; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
  th {{ background: #1e3a5f; color: white; padding: 8px 12px; text-align: left; }}
  td {{ border: 1px solid #cbd5e1; padding: 6px 12px; }}
  tr:nth-child(even) {{ background: #f1f5f9; }}
  code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 3px;
          font-size: 0.9em; color: #1e293b; }}
  strong {{ color: #0f1b2d; }}
  hr {{ border: none; border-top: 1px solid #cbd5e1; margin: 2em 0; }}
  li {{ margin: 4px 0; }}
  a {{ color: #2563eb; }}
  .header {{ background: #0f1b2d; color: white; padding: 20px; margin: -40px -20px 30px;
             text-align: center; }}
  .header h1 {{ color: white; border: none; }}
  .header p {{ color: #94a3b8; margin: 0; }}
</style>
</head>
<body>
<div class="header">
  <h1>NeoXFortress Agent Exploit Report</h1>
  <p>Agent Risk Lab v1.0.0 | Attack Simulation Results</p>
</div>
{body}
</body>
</html>"""

    html_path = os.path.join(output_dir, "report.html")
    with open(html_path, "w") as f:
        f.write(full_html)
    print(f"[*] HTML report: {html_path}")


def generate_report():
    """Generate all report artifacts."""
    output_dir = os.path.join(os.path.dirname(__file__), "outputs")

    print("\n" + "=" * 60)
    print("  NeoXFortress Agent Risk Lab — Report Generator")
    print("=" * 60)

    logs = load_logs(output_dir)
    receipts = load_receipts(output_dir)

    md = generate_markdown(logs, receipts, output_dir)
    generate_html(md, output_dir)

    # Evidence pack manifest
    manifest = {
        "evidence_pack": "NeoXFortress Agent Risk Lab",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "files": [
            {"name": "execution-log.json", "type": "Structured event log"},
            {"name": "receipt-prompt_injection.json", "type": "Agent Accountability Receipt"},
            {"name": "receipt-exfiltration.json", "type": "Agent Accountability Receipt"},
            {"name": "receipt-privilege_escalation.json", "type": "Agent Accountability Receipt"},
            {"name": "report.md", "type": "Exploit report (Markdown)"},
            {"name": "report.html", "type": "Exploit report (HTML)"},
        ],
        "scenarios": list(receipts.keys()),
        "total_events": len(logs),
        "blocked_actions": sum(1 for l in logs if l["outcome"] == "blocked"),
    }

    manifest_path = os.path.join(output_dir, "evidence-manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[*] Evidence manifest: {manifest_path}")

    print(f"\n[*] Evidence pack complete: {len(manifest['files']) + 1} files in {output_dir}/")


if __name__ == "__main__":
    generate_report()

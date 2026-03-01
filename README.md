# NeoXFortress Agent Risk Lab

> Simulate real AI agent attack scenarios. Generate signed evidence artifacts. Prove your defenses work.

**Created by [NeoXFortress LLC](https://neoxfortress.com) — AI Agent Accountability Infrastructure for Regulated Contractors**

---

## What This Is

A simulation lab that demonstrates three categories of AI agent attacks commonly faced in defense and regulated environments:

| Scenario | MITRE ATLAS | What Happens |
|---|---|---|
| **Prompt Injection** | AML.T0051 | Malicious instructions embedded in a document trick the agent into exfiltrating data and disabling logging |
| **Data Exfiltration** | AML.T0048.002 | Agent attempts to send CUI-marked data to Gmail, a .ru domain, and an external file share |
| **Privilege Escalation** | AML.T0044 | Agent attempts to execute shell commands, modify firewall rules, create admin accounts, and access key vaults |

Every attack is **detected and blocked** by the NeoXFortress policy engine. Every blocked action produces a **signed Agent Accountability Receipt** — the same standard used by the [Agent Accountability Receipt schema](https://github.com/NeoXFortress/agent-accountability-receipt).

## Quick Start

```bash
# Clone
git clone https://github.com/NeoXFortress/neox-agent-risk-lab.git
cd neox-agent-risk-lab

# No external dependencies required — pure Python 3.10+

# Run all scenarios
python scenario_runner.py

# Generate exploit report (Markdown + HTML)
python report_generator.py

# Or run everything in one command
python run_all.py
```

## What You Get

After running, the `outputs/` directory contains:

```
outputs/
├── execution-log.json                    ← Structured event log (all scenarios)
├── receipt-prompt_injection.json         ← Signed receipt: injection attack
├── receipt-exfiltration.json             ← Signed receipt: CUI exfiltration attempt
├── receipt-privilege_escalation.json     ← Signed receipt: unauthorized tool access
├── report.md                             ← Agent Exploit Report (Markdown)
├── report.html                           ← Agent Exploit Report (styled HTML)
└── evidence-manifest.json                ← Evidence pack manifest
```

## Architecture

**1-agent sequential pipeline.** No multi-agent coordination needed — these are deterministic attack simulations with policy enforcement.

```
Document/Input → Policy Engine → Tool Wrapper → Decision (ALLOW/DENY/REQUIRES_HUMAN) → Log → Receipt
```

### Components

| File | Purpose |
|---|---|
| `policy_engine.py` | Tool-level access control: allowlist enforcement, domain blocking, CUI content gates, prompt injection scanner |
| `scenario_runner.py` | Executes all 3 attack scenarios, produces structured JSON logs + signed receipts |
| `report_generator.py` | Builds Markdown + HTML exploit report with MITRE ATLAS mapping and CMMC control coverage |
| `run_all.py` | One-command runner: scenarios + report |

### Policy Engine Decisions

| Decision | Meaning |
|---|---|
| `ALLOW` | Tool call permitted under current policy |
| `DENY` | Tool call blocked — logged with rule ID and reason |
| `REQUIRES_HUMAN` | Tool call paused pending human approval |

## CMMC L2 Controls Exercised

| Control | Domain | Scenarios |
|---|---|---|
| SC.L2-3.13.1 | Boundary Protection | Exfiltration, Prompt Injection |
| SC.L2-3.13.2 | CUI Flow Enforcement | Exfiltration |
| SI.L2-3.14.1 | System Integrity | Prompt Injection |
| AC.L2-3.1.1 | Access Control | Exfiltration, Privilege Escalation |
| AC.L2-3.1.2 | Access Control Enforcement | Privilege Escalation |
| AU.L2-3.3.1 | System Auditing | Privilege Escalation |

## Relationship to Agent Accountability Receipt

Each scenario produces a receipt conforming to the [Agent Accountability Receipt schema v0.1.1](https://github.com/NeoXFortress/agent-accountability-receipt). The receipts include:

- SHA-256 hash chain linking every execution step
- HMAC-SHA256 signature for tamper evidence
- Policy snapshot bound to the execution
- Guardrail events with blocked action detail
- CMMC compliance verdict and violated controls

**This lab shows the attack. The receipt proves you caught it.**

## Use Cases

- **Sales demos:** Show prospects what AI agent attacks look like and how your tooling catches them
- **Security assessments:** Generate evidence packs for C3PAO / prime contractor / IG review
- **Training:** Educate teams on AI agent risk vectors with hands-on simulations
- **Red team exercises:** Baseline policy coverage against MITRE ATLAS techniques

---

*Copyright (c) 2026 Julio Berroa / NeoXFortress LLC*

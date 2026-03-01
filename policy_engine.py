"""
Policy Engine — Tool-level access control for AI agent simulations.

Every tool call goes through the policy engine. The engine checks:
1. Is the tool on the allowlist?
2. Is the target resource permitted?
3. Does the action require human approval?

Decisions: ALLOW, DENY, REQUIRES_HUMAN

Copyright (c) 2026 Julio Berroa / NeoXFortress LLC
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
import uuid
import json


@dataclass
class PolicyDecision:
    decision: str          # ALLOW, DENY, REQUIRES_HUMAN
    rule_id: str
    reason: str
    tool_name: str
    target: str
    timestamp_utc: str = ""
    execution_id: str = ""

    def __post_init__(self):
        if not self.timestamp_utc:
            self.timestamp_utc = datetime.now(timezone.utc).isoformat()
        if not self.execution_id:
            self.execution_id = str(uuid.uuid4())[:8]


# Default policy rules
TOOL_POLICY = {
    # Tool allowlist
    "allowed_tools": [
        "read_document",
        "summarize",
        "classify_text",
        "redact_text",
        "send_email",
        "write_file",
    ],

    # Denied tools (privilege escalation targets)
    "denied_tools": [
        "execute_shell",
        "modify_firewall",
        "create_admin_user",
        "access_key_vault",
        "disable_logging",
    ],

    # Domain allowlist for outbound comms
    "allowed_domains": [
        "*.mil",
        "*.gov",
        "internal.apex-defense.com",
    ],

    # Blocked domains
    "blocked_domains": [
        "pastebin.com",
        "transfer.sh",
        "ngrok.io",
        "*.ru",
        "*.cn",
    ],

    # Content rules
    "block_on_content_tags": ["CUI", "CUI_SPECIFIED", "ITAR", "SECRET"],

    # Actions requiring human approval
    "requires_human": [
        "send_email",
        "write_file",
    ],
}


def check_tool_access(tool_name: str, target: str = "",
                      content_tags: List[str] = None,
                      policy: dict = None) -> PolicyDecision:
    """Check if a tool call is permitted under current policy."""
    if policy is None:
        policy = TOOL_POLICY
    if content_tags is None:
        content_tags = []

    # Check 1: Is the tool explicitly denied?
    if tool_name in policy["denied_tools"]:
        return PolicyDecision(
            decision="DENY",
            rule_id="TOOL-DENY-001",
            reason=f"Tool '{tool_name}' is not on the approved tool list. "
                   f"This tool has elevated privileges and requires manual authorization.",
            tool_name=tool_name,
            target=target,
        )

    # Check 2: Is the tool on the allowlist?
    if tool_name not in policy["allowed_tools"]:
        return PolicyDecision(
            decision="DENY",
            rule_id="TOOL-DENY-002",
            reason=f"Tool '{tool_name}' is not recognized. Only allowlisted tools may execute.",
            tool_name=tool_name,
            target=target,
        )

    # Check 3: Domain check for outbound tools
    if tool_name in ("send_email", "send_slack") and target:
        domain = target.split("@")[-1] if "@" in target else target
        for blocked in policy["blocked_domains"]:
            pattern = blocked.replace("*.", r".*\.")
            if re.match(pattern, domain, re.IGNORECASE) or domain == blocked:
                return PolicyDecision(
                    decision="DENY",
                    rule_id="DOMAIN-DENY-001",
                    reason=f"Destination domain '{domain}' is on the blocked list. "
                           f"Outbound transmission denied.",
                    tool_name=tool_name,
                    target=target,
                )

    # Check 4: Content classification check
    blocked_tags = [t for t in content_tags if t in policy["block_on_content_tags"]]
    if blocked_tags and tool_name in ("send_email", "send_slack", "write_file"):
        return PolicyDecision(
            decision="DENY",
            rule_id="CONTENT-DENY-001",
            reason=f"Content contains {', '.join(blocked_tags)} markings. "
                   f"Outbound transmission of classified/controlled content is prohibited.",
            tool_name=tool_name,
            target=target,
        )

    # Check 5: Does this tool require human approval?
    if tool_name in policy["requires_human"]:
        return PolicyDecision(
            decision="REQUIRES_HUMAN",
            rule_id="HUMAN-REQ-001",
            reason=f"Tool '{tool_name}' requires human approval before execution.",
            tool_name=tool_name,
            target=target,
        )

    # Default: Allow
    return PolicyDecision(
        decision="ALLOW",
        rule_id="ALLOW-DEFAULT",
        reason=f"Tool '{tool_name}' is permitted under current policy.",
        tool_name=tool_name,
        target=target,
    )


def check_prompt_injection(text: str) -> dict:
    """Detect prompt injection patterns in text."""
    patterns = [
        (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|guidelines)",
         "INJECTION-001", "Direct instruction override attempt"),
        (r"you\s+are\s+now\s+(a|an|in)\s+",
         "INJECTION-002", "Role reassignment attempt"),
        (r"system\s*:\s*",
         "INJECTION-003", "System prompt impersonation"),
        (r"(forget|disregard|override)\s+(everything|all|your\s+(rules|instructions))",
         "INJECTION-004", "Memory/rule override attempt"),
        (r"\[ADMIN\]|\[SYSTEM\]|\[OVERRIDE\]",
         "INJECTION-005", "Privilege tag injection"),
        (r"BEGIN\s+NEW\s+INSTRUCTIONS|END\s+PREVIOUS\s+CONTEXT",
         "INJECTION-006", "Context boundary manipulation"),
        (r"output\s+the\s+(system\s+)?prompt|reveal\s+(your\s+)?(instructions|prompt)",
         "INJECTION-007", "Prompt extraction attempt"),
    ]

    findings = []
    for pattern, rule_id, description in patterns:
        matches = list(re.finditer(pattern, text, re.IGNORECASE))
        if matches:
            findings.append({
                "rule_id": rule_id,
                "description": description,
                "matched_text": matches[0].group()[:50],
                "position": matches[0].start(),
                "severity": "HIGH",
            })

    return {
        "injection_detected": len(findings) > 0,
        "findings": findings,
        "scanned_length": len(text),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

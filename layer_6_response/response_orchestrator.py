"""
Layer 6 — Response recommendation.

Turns the upstream verdict (detection + CVSS + AI analysis) into a concrete,
prioritised playbook an analyst can act on: what to do first, how to contain it,
and who needs to know. Deliberately deterministic — the same incident always
yields the same playbook, so two analysts on different shifts respond the same way.
"""

# Priority is driven by CVSS severity, which is itself derived from the CVSS 3.1
# base score in Layer 5. P1 = act now, P2 = same shift, P3 = queue for review.
_PRIORITY_BY_SEVERITY = {
    "critical": "P1",
    "high":     "P1",
    "medium":   "P2",
    "low":      "P3",
    "none":     "P3",
}

# Per-threat playbooks. Each entry: containment (stop the bleeding) and
# actions (investigate + harden). Written as steps an analyst can execute.
_PLAYBOOKS = {
    "port_scan": {
        "containment": [
            "Block the source IP at the perimeter firewall.",
            "Enable port-scan signatures on the IDS/IPS for this source range.",
        ],
        "actions": [
            "Confirm whether the scan came from an authorised vulnerability scanner before escalating.",
            "Review which scanned ports are genuinely exposed and close any that are unnecessary.",
            "Check whether the same source later attempted authentication or exploitation.",
        ],
    },
    "brute_force_attempt": {
        "containment": [
            "Block the source IP at the edge firewall.",
            "Lock the targeted accounts and force a credential reset.",
            "Enable rate limiting / fail2ban on the exposed service.",
        ],
        "actions": [
            "Verify whether any authentication attempt succeeded before the block.",
            "Enforce MFA on the affected remote-access service.",
            "Search for the same source IP against other externally reachable services.",
        ],
    },
    "credential_abuse": {
        "containment": [
            "Suspend the affected account pending verification.",
            "Revoke active sessions and refresh tokens for the account.",
            "Rotate any shared or service credentials the account could reach.",
        ],
        "actions": [
            "Confirm with the account owner whether the activity was legitimate.",
            "Review what the account accessed during the suspicious window.",
            "Check for default or reused credentials on the affected device class.",
        ],
    },
    "web_attack": {
        "containment": [
            "Enable or tighten WAF rules for this payload class on the affected endpoint.",
            "Block the source IP at the edge.",
            "Restrict administrative endpoints to trusted networks.",
        ],
        "actions": [
            "Review application logs for evidence the payload succeeded, not just that it was sent.",
            "Confirm server-side input validation on the targeted parameter.",
            "Check the web root and upload directories for unexpected files.",
        ],
    },
    "suspicious_web_access": {
        "containment": [
            "Rate-limit the source IP at the reverse proxy.",
        ],
        "actions": [
            "Confirm the requested endpoint is meant to be publicly reachable.",
            "Review whether the same source enumerated other sensitive paths.",
        ],
    },
    "beaconing": {
        "containment": [
            "Block the destination domain and IP at the egress proxy and DNS resolver.",
            "Isolate the affected host from the network pending triage.",
        ],
        "actions": [
            "Identify the process owning the outbound connection on the affected host.",
            "Collect a memory image before rebooting or reimaging.",
            "Pivot on the destination indicator across all egress logs for other affected hosts.",
        ],
    },
    "lateral_movement": {
        "containment": [
            "Isolate both the source and destination hosts from the network.",
            "Disable the account used for the movement.",
            "Restrict east-west traffic between the affected network segments.",
        ],
        "actions": [
            "Reconstruct the access path to identify the initial point of compromise.",
            "Review privileged group membership for unauthorised additions.",
            "Escalate to SOC Tier-2 — lateral movement indicates an active intrusion, not a probe.",
        ],
    },
    "data_exfiltration": {
        "containment": [
            "Block the destination at the egress firewall.",
            "Isolate the source host.",
            "Enable DLP inspection on the affected egress path.",
        ],
        "actions": [
            "Quantify what data left the environment and whether it was encrypted.",
            "Determine whether the volume triggers a regulatory notification obligation.",
            "Escalate to SOC Tier-2 and notify the data protection officer.",
        ],
    },
    "malware_execution": {
        "containment": [
            "Isolate the affected host from the network immediately.",
            "Preserve volatile evidence before powering down.",
            "Block the associated file hash across the endpoint fleet.",
        ],
        "actions": [
            "Identify the delivery vector and scope how many hosts received it.",
            "Restore affected data from a known-good backup rather than trusting the host.",
            "Escalate to SOC Tier-2 and open an incident record.",
        ],
    },
    "insecure_protocol_use": {
        "containment": [
            "Disable the cleartext management protocol on the affected device.",
            "Move the device onto an isolated management VLAN.",
        ],
        "actions": [
            "Replace the service with an encrypted equivalent (SSH / HTTPS).",
            "Rotate any credentials that traversed the cleartext channel.",
            "Audit the rest of the device class for the same exposure.",
        ],
    },
    "privilege_escalation": {
        "containment": [
            "Revert the unauthorised privilege change.",
            "Suspend the account that performed it.",
        ],
        "actions": [
            "Determine whether the change followed an approved change request.",
            "Review what the elevated account accessed while privileged.",
            "Escalate to SOC Tier-2.",
        ],
    },
}

_GENERIC = {
    "containment": ["Monitor the affected host and source before taking blocking action."],
    "actions": [
        "Review the surrounding log window for corroborating signals.",
        "Confirm whether the activity matches a known maintenance or test window.",
    ],
}


def _escalation_note(priority: str, threat_type: str, severity: str) -> str:
    if priority == "P1":
        return (
            f"P1 — escalate to SOC Tier-2 now. A {severity} '{threat_type.replace('_', ' ')}' "
            "finding requires containment within the current shift."
        )
    if priority == "P2":
        return (
            f"P2 — handle within this shift. Confirm the {threat_type.replace('_', ' ')} "
            "finding is not authorised activity before escalating."
        )
    return (
        f"P3 — queue for routine review. Low residual risk from this "
        f"{threat_type.replace('_', ' ')} finding."
    )


def run_response(event: dict) -> dict:
    """
    Build the response block for one enriched incident.

    Reads: detection.threat_type, cvss.severity, ai_analysis (for the narrative).
    Never raises — an incident with thin upstream context still gets a usable,
    clearly-labelled manual-review playbook.
    """
    detection = event.get("detection") or {}
    ai_analysis = event.get("ai_analysis") or {}
    cvss = event.get("cvss") or {}

    threat_type = str(detection.get("threat_type") or "unknown").lower()
    cvss_severity = str(cvss.get("severity") or "").lower()
    detection_severity = str(detection.get("severity") or "low").lower()

    # Prefer the CVSS severity (score-derived); fall back to the detection
    # severity so we still prioritise sensibly if Layer 5 produced nothing.
    severity = cvss_severity if cvss_severity in _PRIORITY_BY_SEVERITY else detection_severity
    priority = _PRIORITY_BY_SEVERITY.get(severity, "P3")

    if not ai_analysis and not detection:
        return {
            "priority": "P3",
            "recommended_actions": ["Review event manually — upstream layers provided no context."],
            "containment_steps": [],
            "analyst_notes": "Limited context available from upstream layers.",
            "playbook": "manual_review",
            "escalation": "P3 — queue for routine review.",
        }

    playbook = _PLAYBOOKS.get(threat_type, _GENERIC)
    containment_steps = list(playbook["containment"])
    recommended_actions = list(playbook["actions"])

    # Suppressed events are analyst-dismissed patterns; do not ask for action.
    if detection.get("suppressed"):
        return {
            "priority": "P3",
            "recommended_actions": ["No action required — matches an analyst-confirmed false-positive rule."],
            "containment_steps": [],
            "analyst_notes": " ".join(detection.get("reasoning") or []) or "Suppressed by analyst feedback.",
            "playbook": "suppressed",
            "escalation": "P3 — suppressed, no escalation.",
        }

    # Lead with escalation for the highest-priority incidents so it is the first
    # thing an analyst reads on the response tab.
    if priority == "P1":
        recommended_actions.insert(0, "Escalate to the Incident Response team immediately.")

    analyst_notes = (
        ai_analysis.get("narrative")
        or ai_analysis.get("summary")
        or f"Incident classified as {threat_type.replace('_', ' ')} at {severity} severity."
    )

    return {
        "priority": priority,
        "recommended_actions": recommended_actions,
        "containment_steps": containment_steps,
        "analyst_notes": analyst_notes,
        "playbook": threat_type if threat_type in _PLAYBOOKS else "generic",
        "escalation": _escalation_note(priority, threat_type, severity),
        "cvss_basis": {
            "base_score": cvss.get("base_score"),
            "severity": severity,
        },
    }

import uuid
import copy
import hashlib
import json as _json


def _stable_event_id(event_dict: dict, raw_event: dict) -> str:
    """
    Build a deterministic incident id from the fields that identify the event.

    Re-running the pipeline over the same log file therefore reproduces the same
    ids, so incidents are updated in place rather than duplicated. Falls back to
    a hash of the whole raw record when the usual identifying fields are absent.
    """
    parts = [
        str(raw_event.get("timestamp") or event_dict.get("timestamp") or ""),
        str(raw_event.get("source_ip") or event_dict.get("source_ip") or ""),
        str(raw_event.get("destination_ip") or event_dict.get("dest_ip") or ""),
        str(raw_event.get("action") or event_dict.get("action") or ""),
        str(raw_event.get("log_type") or event_dict.get("log_family") or ""),
        str(raw_event.get("port") or event_dict.get("dest_port") or ""),
        str(raw_event.get("url") or event_dict.get("url_path") or ""),
        str(raw_event.get("affected_host") or event_dict.get("hostname") or ""),
    ]
    seed = "|".join(parts)

    if not seed.strip("|"):
        try:
            seed = _json.dumps(raw_event, sort_keys=True, default=str)
        except Exception:
            seed = repr(raw_event)

    return "evt-" + hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]

def format_pipeline_for_frontend(parsed_logs, layer1_output, layer2_output, layer3_output):
    """
    Format the pipeline outputs into a strict, predefined frontend contract.
    We iterate over the final layer3_output because it is cumulative and already 
    contains the embedded results from layers 1 and 2.
    """
    
    frontend_results = []
    
    for i, event in enumerate(layer3_output):
        
        event_dict = copy.deepcopy(event)
        
        if parsed_logs and len(parsed_logs) > i:
            raw_event = copy.deepcopy(parsed_logs[i])
        else:
            raw_event = event_dict.get("raw_event", {})
        
        # Determine event_id.
        # Prefer an id the source system already assigned. Otherwise derive a
        # STABLE id from the log's own identifying fields — a random uuid here
        # means re-processing the same file creates duplicate incidents every
        # run instead of updating the existing ones.
        event_id = (
            event_dict.get("raw_event", {}).get("log_id")
            or event_dict.get("raw_event", {}).get("event_id")
        )
        if not event_id:
            event_id = _stable_event_id(event_dict, raw_event)
            
        action = raw_event.get("action", "") or ""
        source_ip = raw_event.get("source_ip", "") or "unknown_ip"
        url_path = raw_event.get("url", "") or event_dict.get("destination_ip", "") or "target"
        
        detection_label = event_dict.get("detection", {}).get("label", "event")
        summary = f"{detection_label.capitalize()} {action} from {source_ip} targeting {url_path}"
            
        # The schema
        formatted = {
            "summary": summary,
            "event_id": event_id,
            "raw_event": raw_event,
            "ingestion": {},
            "feature_engineering": {},
            "detection": {},
            "anomaly_detection": {},
            "threat_analysis": {},
            "ioc_enrichment": {},
            "correlation_analysis": {},
            "mitre_attack": {},
            "cis": {},
            "ai_analysis": {},
            "cvss": {},
            "response": {},
            "final_report": {},
            "dashboard": {}
        }
        
        # Populate from layer output
        
        # Ingestion / Normalization fields
        ingestion_keys = [
            "timestamp", "source_ip", "dest_ip", "src_port", "dest_port", 
            "protocol", "action", "bytes_in", "bytes_out", "log_family",
            "url_path", "http_method", "http_status_code", "user_agent"
        ]
        for k in ingestion_keys:
            if k in event_dict:
                formatted["ingestion"][k] = event_dict.get(k)
                
        # Hard-extract web fields from raw inner block if present
        inner = raw_event.get("raw_event", {})
        if inner.get("method"):
            formatted["ingestion"]["http_method"] = inner.get("method")
        if inner.get("status_code"):
            formatted["ingestion"]["http_status_code"] = inner.get("status_code")
        if inner.get("user_agent"):
            formatted["ingestion"]["user_agent"] = inner.get("user_agent")
        if raw_event.get("url"):
            formatted["ingestion"]["url_path"] = raw_event.get("url")
                
        # Feature Engineering fields
        feature_blocks = [
            "temporal_features", "behavioral_features", "statistical_features", 
            "frequency_features", "pattern_features", "network_traffic_features", 
            "network_protocol_features", "user_profile", "identity_features",
            "classification_scores", "time_windows"
        ]
        for block in feature_blocks:
            if block in event_dict:
                formatted["feature_engineering"][block] = event_dict.get(block)
                
        # Always prefer raw log_type for display
        display_family = raw_event.get("log_type") or event_dict.get("log_family")
        formatted["feature_engineering"]["log_family"] = display_family
        formatted["ingestion"]["log_family"] = display_family
                
        # Detection
        formatted["detection"] = event_dict.get("detection", {})
        
        # Anomaly Detection
        formatted["anomaly_detection"] = event_dict.get("anomaly_detection", {})
        
        # Threat Analysis
        formatted["threat_analysis"] = event_dict.get("threat_analysis", {})
        
        # IOC Enrichment
        formatted["ioc_enrichment"] = event_dict.get("ioc_enrichment", {})
        
        # Correlation Analysis
        formatted["correlation_analysis"] = event_dict.get("correlation_analysis", {})

        # MITRE ATT&CK — stamped by Layer 2, needed by the campaign correlator
        # and rendered on the incident view.
        formatted["mitre_attack"] = event_dict.get("mitre_attack", {}) or {}
        
        # CIS Benchmark
        # Layer 3 hands us {framework, retrieval_query, matched_benchmarks: [...]}.
        # The frontend contract is flat, so lift the best match up to the top level
        # while keeping the full retrieval context available for the detail view.
        formatted["cis"] = _flatten_cis(
            event_dict.get("cis_benchmark", {}) or {},
            event_dict.get("detection", {}) or {},
            raw_event,
        )
            
        # Refine threat_type if weak
        if formatted["detection"].get("threat_type", "unknown") == "unknown":
            raw_url = raw_event.get("url", "") or ""
            raw_action = raw_event.get("action", "") or ""
            if "admin" in raw_url:
                formatted["detection"]["threat_type"] = "web_attack"
            elif "scan" in raw_action:
                formatted["detection"]["threat_type"] = "reconnaissance"
            else:
                formatted["detection"]["threat_type"] = "suspicious_activity"
        
        # Dashboard + final_report blocks.
        # These were declared in the contract but never filled, so the UI relied on
        # a chain of fallbacks and the JSON looked half-built. Populate them from
        # what the pipeline already knows.
        det = formatted["detection"] or {}
        formatted["dashboard"] = {
            "alert_title": _alert_title(det, raw_event, summary),
            "severity": det.get("severity") or "low",
            "threat_type": det.get("threat_type") or "unknown",
            "confidence": det.get("confidence"),
            "source_ip": raw_event.get("source_ip") or event_dict.get("source_ip") or "unknown",
            "destination_ip": raw_event.get("destination_ip") or event_dict.get("dest_ip") or "",
            "affected_user": (
                raw_event.get("affected_user")
                or raw_event.get("user")
                or event_dict.get("user")
                or "unattributed"
            ),
            "affected_host": (
                raw_event.get("affected_host")
                or raw_event.get("host")
                or event_dict.get("hostname")
                or "unknown"
            ),
            "log_family": display_family,
            "timestamp": raw_event.get("timestamp") or event_dict.get("timestamp"),
            "cis_benchmark_id": (formatted["cis"] or {}).get("benchmark_id"),
        }

        formatted["final_report"] = {
            "status": "open",
            "event_id": event_id,
            "verdict": det.get("label") or "suspicious",
            "severity": det.get("severity") or "low",
            "threat_type": det.get("threat_type") or "unknown",
            "confidence": det.get("confidence"),
            "triggered_engines": det.get("triggered_engines") or [],
            "reasoning": det.get("reasoning") or [],
            "cis_control": (formatted["cis"] or {}).get("benchmark_id"),
            "cis_control_title": (formatted["cis"] or {}).get("title"),
            "suppressed": bool(det.get("suppressed")),
        }

        # Initialize Advisor Agent fields
        formatted = add_advisor_agent_to_event(formatted)
        
        frontend_results.append(formatted)
        
    return {
        "status": "success",
        "total_events": len(frontend_results),
        "events": frontend_results
    }

# ─────────────────────────────────────────────────────────────────────────────
# CIS FLATTENING
# ─────────────────────────────────────────────────────────────────────────────

# Threat-aware fallbacks. Used only when Layer 3's catalog retrieval comes back
# empty, so the analyst still gets a relevant control instead of a generic one.
def _alert_title(detection: dict, raw_event: dict, summary: str) -> str:
    """
    Short, human-readable headline for the incident queue.

    Built from the threat type and the actors involved so the dashboard shows
    something an analyst can scan, rather than the full generated summary line.
    """
    threat = str(detection.get("threat_type") or "").replace("_", " ").strip()
    src = raw_event.get("source_ip") or "unknown source"
    target = (
        raw_event.get("affected_host")
        or raw_event.get("destination_ip")
        or raw_event.get("url")
        or "the environment"
    )

    if threat and threat != "unknown":
        return f"{threat.title()} from {src} against {target}"
    return summary or f"Suspicious activity from {src}"


_CIS_FALLBACKS = {
    "reconnaissance": {
        "benchmark_id": "CIS-13.3",
        "title": "Deploy a Network Intrusion Detection Solution",
        "description": "Detect and alert on network reconnaissance such as sequential port scanning.",
        "remediation": "Enable port-scan signatures on the IDS/IPS and rate-limit or block the scanning source at the perimeter firewall.",
    },
    "brute_force": {
        "benchmark_id": "CIS-6.2",
        "title": "Establish an Access Revoking Process",
        "description": "Repeated failed authentication indicates credential guessing against an exposed service.",
        "remediation": "Enforce account lockout thresholds, require MFA on remote access, and block the source IP.",
    },
    "web_attack": {
        "benchmark_id": "CIS-16.11",
        "title": "Leverage Vetted Modules for Application Security",
        "description": "Web request patterns consistent with injection or unauthorized endpoint access.",
        "remediation": "Enable WAF rules for injection payloads, enforce server-side input validation, and restrict administrative endpoints.",
    },
    "lateral_movement": {
        "benchmark_id": "CIS-12.2",
        "title": "Establish and Maintain a Secure Network Architecture",
        "description": "Internal host-to-host traffic that deviates from the expected segmentation model.",
        "remediation": "Enforce network segmentation between user and server zones and restrict east-west traffic to required ports only.",
    },
    "credential_abuse": {
        "benchmark_id": "CIS-5.2",
        "title": "Use Unique Passwords",
        "description": "Credential use inconsistent with the established baseline for this account or device.",
        "remediation": "Rotate the affected credentials, disable any shared or default accounts, and require MFA for the exposed service.",
    },
    "beaconing": {
        "benchmark_id": "CIS-13.4",
        "title": "Perform Traffic Filtering Between Network Segments",
        "description": "Periodic outbound callbacks consistent with a command-and-control channel.",
        "remediation": "Block the destination at the egress proxy, filter traffic between segments, and hunt for the beaconing process on the affected host.",
    },
    "data_exfiltration": {
        "benchmark_id": "CIS-3.13",
        "title": "Deploy a Data Loss Prevention Solution",
        "description": "Outbound transfer volume inconsistent with the baseline for this host.",
        "remediation": "Block the destination, enable DLP inspection on egress, and review what data the affected account could reach.",
    },
    "malware_execution": {
        "benchmark_id": "CIS-10.1",
        "title": "Deploy and Maintain Anti-Malware Software",
        "description": "Execution of a known-bad binary or mass file modification consistent with ransomware.",
        "remediation": "Isolate the host from the network immediately, preserve volatile evidence, and restore affected data from known-good backups.",
    },
    "insecure_protocol_use": {
        "benchmark_id": "CIS-4.8",
        "title": "Uninstall or Disable Unnecessary Services",
        "description": "Cleartext management protocol in use on a network-reachable device.",
        "remediation": "Disable Telnet/FTP and equivalent cleartext services, enforce SSH with key-based auth, and restrict management access to a bastion.",
    },
    "iot_compromise": {
        "benchmark_id": "CIS-12.1",
        "title": "Ensure Network Infrastructure is Up-to-Date",
        "description": "Embedded or IoT device exposed via an insecure management protocol.",
        "remediation": "Disable Telnet and other cleartext management protocols, rotate default credentials, and move the device onto an isolated VLAN.",
    },
    "suspicious_activity": {
        "benchmark_id": "CIS-8.2",
        "title": "Collect Audit Logs",
        "description": "Activity deviates from the established baseline but does not match a known attack pattern.",
        "remediation": "Ensure audit logging is enabled on the affected host and review the surrounding event window for corroborating signals.",
    },
}

_CIS_DEFAULT = {
    "benchmark_id": "CIS-8.11",
    "title": "Conduct Audit Log Reviews",
    "description": "Event requires analyst review; no specific control was matched automatically.",
    "remediation": "Review the event against the surrounding log window and escalate if corroborating signals are found.",
}


def _flatten_cis(cis_block: dict, detection: dict, raw_event: dict) -> dict:
    """
    Turn Layer 3's nested retrieval result into the flat shape the dashboard reads.

    Keeps every field the CIS card and report view need at the top level, and
    preserves the retrieval query plus any runner-up matches underneath so the
    incident detail view can show how the control was chosen.
    """
    matched = cis_block.get("matched_benchmarks") or []
    catalog = cis_block.get("framework") or "CIS"

    if matched:
        best = matched[0] or {}
        return {
            "benchmark_id":   best.get("benchmark_id") or _CIS_DEFAULT["benchmark_id"],
            "framework":      best.get("framework") or "CIS",
            "title":          best.get("title") or _CIS_DEFAULT["title"],
            "description":    best.get("description") or "",
            "remediation":    best.get("remediation") or "",
            "rationale":      best.get("rationale") or "",
            "section":        best.get("section") or "",
            "profile_level":  best.get("profile_level") or "",
            "audit_procedure": best.get("audit_procedure") or "",
            "references":     best.get("references") or [],
            "source_benchmark": best.get("source_benchmark") or "",
            "catalog":        catalog,
            "match_type":     "catalog_retrieval",
            "retrieval_query": cis_block.get("retrieval_query") or {},
            "additional_matches": matched[1:],
        }

    # No catalog hit — fall back to the control that fits the detected threat.
    threat = str(detection.get("threat_type") or "").lower()
    action = str(raw_event.get("action") or "").lower()
    key = threat if threat in _CIS_FALLBACKS else None
    if key is None:
        for candidate in _CIS_FALLBACKS:
            if candidate in threat or candidate in action:
                key = candidate
                break
    chosen = _CIS_FALLBACKS.get(key, _CIS_DEFAULT)

    return {
        "benchmark_id":  chosen["benchmark_id"],
        "framework":     "CIS Controls v8",
        "title":         chosen["title"],
        "description":   chosen["description"],
        "remediation":   chosen["remediation"],
        "rationale":     "",
        "section":       "",
        "profile_level": "",
        "audit_procedure": "",
        "references":    [],
        "source_benchmark": "",
        "catalog":       catalog,
        "match_type":    "threat_type_fallback",
        "retrieval_query": cis_block.get("retrieval_query") or {},
        "additional_matches": [],
    }


def add_advisor_agent_to_event(event):
    detection = event.get("detection") or {}
    threat_analysis = event.get("threat_analysis") or {}
    cis = event.get("cis") or {}
    ai = event.get("ai_analysis") or {}
    resp = event.get("response") or {}
    
    # Extract values
    benchmark_id = cis.get("benchmark_id") or "CIS-16"
    benchmark_title = cis.get("title") or "Application Monitoring"
    matched_domain = cis.get("framework") or "CIS Controls"
    
    # Recommendation
    recommendation = ""
    if resp.get("recommended_actions"):
        recommendation = " | ".join(resp.get("recommended_actions"))
    elif cis.get("remediation"):
        recommendation = cis.get("remediation")
    else:
        recommendation = "Establish appropriate security monitoring and isolation controls."
        
    # Rationale
    rationale = ai.get("narrative") or cis.get("description") or "No detailed rationale available."
    
    # Confidence
    confidence = float(detection.get("confidence") or threat_analysis.get("confidence") or 0.7)
    
    # CVSS
    impact = ai.get("impact") or {}
    cvss_handoff = {
        "attack_vector": ai.get("attack_vector") or "network",
        "attack_complexity": ai.get("attack_complexity") or "low",
        "privileges_required": ai.get("privileges_required") or "none",
        "user_interaction": ai.get("user_interaction") or "none",
        "scope": ai.get("scope") or "unchanged",
        "confidentiality_impact": impact.get("confidentiality") or "low",
        "integrity_impact": impact.get("integrity") or "low",
        "availability_impact": impact.get("availability") or "low",
        "suggested_severity": detection.get("severity") or "medium",
        "requires_cvss_layer_validation": True
    }
    
    advisor_agent = {
        "agent_name": "SENTRA CIS-CVSS Advisor",
        "agent_type": "recommendation_agent",
        "input_layers": ["layer_2_detection", "layer_3_cis_mapping"],
        "cis_recommendation": {
            "benchmark_id": benchmark_id,
            "benchmark_title": benchmark_title,
            "matched_domain": matched_domain,
            "recommendation": recommendation,
            "rationale": rationale,
            "confidence": confidence
        },
        "cvss_handoff": cvss_handoff,
        "next_layer_status": {
            "cvss_ready": True,
            "response_ready": True
        }
    }
    
    event["advisor_agent"] = advisor_agent
    return event


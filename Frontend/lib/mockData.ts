/* eslint-disable @typescript-eslint/no-explicit-any */
import { asList } from "@/lib/utils";

export type EventPipeline = {
  event_id: string;
  // Human-readable one-line description produced by the backend formatter.
  summary?: string;
  raw_event: any;

  ingestion: any;
  feature_engineering: any;

  anomaly_detection: any;
  threat_analysis: any;
  ioc_enrichment: any;
  correlation_analysis: any;

  detection: {
    label: string;
    severity: "low" | "medium" | "high" | "critical";
    confidence: number;
    threat_type?: string;
    reasoning?: string[];
    triggered_engines?: string[];
    suppressed?: boolean;
  };

  cis: any;

  // Stamped by Layer 2 (ATT&CK) and Layer 2.5 (campaign correlation).
  mitre_attack?: {
    primary?: { technique_id?: string; technique_name?: string; tactic_name?: string; url?: string };
    techniques?: { technique_id: string; technique_name: string; tactic_name: string; url: string }[];
    tactics?: { id: string; name: string; order: number }[];
    kill_chain_stage?: string;
    kill_chain_order?: number;
  };
  campaign?: {
    campaign_id: string;
    name: string;
    severity: string;
    incident_count: number;
    furthest_stage: string;
    progression_pct: number;
  } | null;
  ai_analysis: {
    summary?: string;
    blast_radius?: string;
    confidence_note?: string;
    // Model/rule confidence in the analysis, 0-1.
    confidence?: number;
    // NEW: AI STORYTELLING FIELDS
    one_liner?: string;
    intent?: string;
    narrative?: string;
    attack_vector?: string;
    impact?: {
      confidentiality?: string;
      integrity?: string;
      availability?: string;
    };
    next_steps?: string[];
  };
  cvss: {
    base_score: number;
    severity: string;
    vector_string?: string;
  };
  response: {
    priority: string;
    recommended_actions: string[];
    containment_steps?: string[];
    analyst_notes?: string;
    playbook?: string;
    escalation?: string;
    // Layer 6 human-in-the-loop gate: which containment steps can auto-execute
    // and which are held because they could interrupt a live service.
    containment_plan?: {
      action: string;
      execution: "auto" | "requires_approval";
      blast_radius: "contained" | "host-affecting" | "service-affecting";
      rationale: string;
    }[];
    auto_executable?: number;
    awaiting_approval?: number;
    requires_human_approval?: boolean;
    cvss_basis?: { base_score?: number; severity?: string };
  };
  status?: string;
  analyst_label?: string | null;
  final_report: any;
  dashboard: {
    alert_title: string;
    severity: string;
    cvss_score: number;
    source_ip?: string;
    affected_user?: string;
  };
};

const emptyPipeline: EventPipeline = {
  event_id: "evt-empty",
  raw_event: {},
  ingestion: {},
  feature_engineering: {},
  anomaly_detection: {},
  threat_analysis: {},
  ioc_enrichment: {},
  correlation_analysis: {},
  detection: {
    label: "Unknown",
    severity: "low",
    confidence: 0,
    threat_type: "unknown",
    reasoning: [],
    triggered_engines: [],
  },
  cis: {},
  ai_analysis: {
    summary: "",
    blast_radius: "",
    confidence_note: "",
    one_liner: "",
    intent: "Unknown",
    narrative: "",
    attack_vector: "",
    impact: {
      confidentiality: "Low",
      integrity: "Low",
      availability: "Low",
    },
    next_steps: [],
  },
  cvss: {
    base_score: 0,
    severity: "low",
    vector_string: "N/A",
  },
  response: {
    priority: "P4",
    recommended_actions: [],
    containment_steps: [],
  },
  final_report: {},
  dashboard: {
    alert_title: "No Incident",
    severity: "low",
    cvss_score: 0,
    source_ip: "N/A",
    affected_user: "N/A",
  },
};

export function createEmptyPipeline(): EventPipeline {
  return structuredClone(emptyPipeline);
}

export function normalizePipeline(input: any): EventPipeline {
  const base = createEmptyPipeline();
  const severity = (input?.detection?.severity ?? base.detection.severity)
    .toString()
    .toLowerCase();
  const safeSeverity: EventPipeline["detection"]["severity"] =
    severity === "critical" || severity === "high" || severity === "medium" || severity === "low"
      ? severity
      : "low";

  return {
    event_id: input?.event_id ?? base.event_id,
    raw_event: input?.raw_event ?? base.raw_event,
    ingestion: input?.ingestion ?? base.ingestion,
    feature_engineering: input?.feature_engineering ?? base.feature_engineering,
    anomaly_detection: input?.anomaly_detection ?? base.anomaly_detection,
    threat_analysis: input?.threat_analysis ?? base.threat_analysis,
    ioc_enrichment: input?.ioc_enrichment ?? base.ioc_enrichment,
    correlation_analysis: input?.correlation_analysis ?? base.correlation_analysis,
    detection: {
      label: input?.detection?.label ?? base.detection.label,
      severity: safeSeverity,
      confidence: Number(input?.detection?.confidence ?? base.detection.confidence),
      threat_type: input?.detection?.threat_type ?? base.detection.threat_type,
      reasoning: asList(input?.detection?.reasoning),
      triggered_engines: asList(input?.detection?.triggered_engines),
    },
    cis: input?.cis ?? base.cis,
    ai_analysis: {
      summary: input?.ai_analysis?.summary ?? base.ai_analysis.summary,
      blast_radius: input?.ai_analysis?.blast_radius ?? base.ai_analysis.blast_radius,
      confidence_note: input?.ai_analysis?.confidence_note ?? base.ai_analysis.confidence_note,
      one_liner: input?.ai_analysis?.one_liner ?? base.ai_analysis.one_liner,
      intent: input?.ai_analysis?.intent ?? base.ai_analysis.intent,
      narrative: input?.ai_analysis?.narrative ?? base.ai_analysis.narrative,
      attack_vector: input?.ai_analysis?.attack_vector ?? base.ai_analysis.attack_vector,
      impact: {
        confidentiality: input?.ai_analysis?.impact?.confidentiality ?? base.ai_analysis.impact?.confidentiality,
        integrity: input?.ai_analysis?.impact?.integrity ?? base.ai_analysis.impact?.integrity,
        availability: input?.ai_analysis?.impact?.availability ?? base.ai_analysis.impact?.availability,
      },
      next_steps: asList(input?.ai_analysis?.next_steps),
    },
    cvss: {
      base_score: Number(input?.cvss?.base_score ?? base.cvss.base_score),
      severity: input?.cvss?.severity ?? base.cvss.severity,
      vector_string: input?.cvss?.vector_string ?? base.cvss.vector_string,
    },
    response: {
      priority: input?.response?.priority ?? base.response.priority,
      recommended_actions: asList(input?.response?.recommended_actions),
      containment_steps: asList(input?.response?.containment_steps),
    },
    final_report: input?.final_report ?? base.final_report,
    dashboard: {
      alert_title: input?.dashboard?.alert_title ?? base.dashboard.alert_title,
      severity: input?.dashboard?.severity ?? base.dashboard.severity,
      cvss_score: Number(input?.dashboard?.cvss_score ?? base.dashboard.cvss_score),
      source_ip: input?.dashboard?.source_ip ?? base.dashboard.source_ip,
      affected_user: input?.dashboard?.affected_user ?? base.dashboard.affected_user,
    },
  };
}

export const mockPipelines: EventPipeline[] = [
  normalizePipeline({
    event_id: "evt-2026-04-001",
    raw_event: {
      timestamp: "2026-04-06T07:11:22Z",
      event_name: "Suspicious PowerShell Execution",
      host: "workstation-17",
      user: "alex.m",
      source_ip: "185.14.22.91",
      process: "powershell.exe",
      command:
        "powershell -nop -w hidden -enc SQBtAHAAbwByAHQALQBNAG8AZAB1AGwAZQAgQml0cwBUcmFuc2Zlcg==",
    },
    ingestion: {
      source: "Microsoft Defender XDR",
      collector: "fluent-bit",
      parsed_fields: 38,
      integrity_hash: "0x4af9b2",
    },
    feature_engineering: {
      suspicious_command_entropy: 0.91,
      rare_parent_process: true,
      geo_velocity_risk: "high",
    },
    anomaly_detection: {
      model: "IsolationForest-v4",
      anomaly_score: 0.94,
      baseline_deviation: "+282%",
    },
    threat_analysis: {
      mitre_tactics: ["Execution", "Defense Evasion"],
      mitre_techniques: ["T1059.001", "T1027"],
    },
    ioc_enrichment: {
      domain_hits: ["cdn-update-check.net"],
      hash_reputation: "malicious",
      ip_reputation: "high-risk ASN",
    },
    correlation_analysis: {
      linked_events: 11,
      kill_chain_stage: "Installation",
      campaign_similarity: "Lazarus-leaning",
    },
    detection: {
      label: "Malicious Script Execution",
      severity: "critical",
      confidence: 0.97,
      threat_type: "Command and Control",
      reasoning: [
        "Encoded PowerShell payload detected",
        "Host contacted known high-risk infrastructure",
        "Behavior diverges from user baseline",
      ],
      triggered_engines: ["UEBA", "Threat Intel", "Behavioral ML"],
    },
    cis: {
      controls_impacted: ["CIS 8.2", "CIS 8.7", "CIS 13.1"],
      compliance_risk: "high",
    },
    ai_analysis: {
      summary:
        "Incident likely represents an initial foothold attempt using obfuscated script execution and beaconing behavior.",
      blast_radius: "single endpoint with lateral movement risk",
      confidence_note: "Model consensus 3/3",
      one_liner: "AI detected a high-confidence brute force attack targeting admin account during off-hours.",
      intent: "Initial Compromise & Command and Control",
      narrative:
        "Our AI threat analysis has identified a sophisticated, multi-stage attack chain. The attack began with an encoded PowerShell payload—a known obfuscation technique used by advanced threat actors to evade traditional defenses. The payload was executed on a domain workstation (workstation-17) belonging to user 'alex.m', and our behavioral AI detected an immediate deviation from the user's baseline activity pattern. Within seconds of execution, the endpoint initiated outbound connections to a known malicious infrastructure node (cdn-update-check.net) hosted on a high-risk ASN. This beaconing behavior, combined with the execution chain, strongly suggests the attacker has established a command-and-control channel and is now in position to move laterally across your network.",
      attack_vector:
        "The attack likely originated from a spear-phishing email or compromised external service, delivering the encoded PowerShell payload. Once executed with the user's privileges, the payload established a reverse shell connection to attacker-controlled infrastructure.",
      impact: {
        confidentiality: "HIGH - Attacker can read sensitive data",
        integrity: "HIGH - Attacker can modify system state",
        availability: "MEDIUM - Attacker could disrupt services",
      },
      next_steps: [
        "Immediately isolate workstation-17 from the network",
        "Block the detected C2 domains and IPs at the perimeter",
        "Revoke and rotate all credentials for user alex.m",
        "Hunt for lateral movement beyond this endpoint",
        "Preserve volatile memory for forensic analysis",
      ],
    },
    cvss: {
      base_score: 9.1,
      severity: "critical",
      vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },
    response: {
      priority: "P1",
      recommended_actions: [
        "Isolate workstation-17 from network",
        "Block source IP and destination domain",
        "Reset user credentials and revoke tokens",
      ],
      containment_steps: [
        "Collect volatile memory",
        "Acquire endpoint forensic image",
        "Hunt for matching IOCs across tenant",
      ],
    },
    final_report: {
      owner: "SOC Tier-2",
      status: "Open",
      timeline: ["Alert raised", "Triage completed", "Containment pending"],
    },
    dashboard: {
      alert_title: "Critical Endpoint Compromise Suspected",
      severity: "critical",
      cvss_score: 9.1,
      source_ip: "185.14.22.91",
      affected_user: "alex.m",
    },
  }),
];

export const scenarioOptions = [
  { value: "web", label: "Web Attack Scenario" },
  { value: "network", label: "Network Attack Scenario" },
  { value: "iot", label: "IoT Attack Scenario" },
] as const;

const scenarioMap: Record<(typeof scenarioOptions)[number]["value"], EventPipeline> = {
  web: normalizePipeline({
    event_id: "evt-web-001",
    raw_event: {
      timestamp: "2026-04-06T10:12:00Z",
      event_name: "Suspicious Web Shell Upload",
      host: "web-frontend-12",
      source_ip: "203.0.113.41",
      user_agent: "sqlmap/1.7",
      uri: "/uploads/shell.aspx",
      method: "POST",
    },
    ingestion: { source: "WAF", collector: "edge-agent", parsed_fields: 27 },
    feature_engineering: { request_rate_spike: true, unusual_user_agent: true, payload_entropy: 0.88 },
    anomaly_detection: { model: "XGBoost-RequestRisk", anomaly_score: 0.91 },
    threat_analysis: { mitre_tactics: ["Initial Access", "Execution"], mitre_techniques: ["T1190", "T1505.003"] },
    ioc_enrichment: { domain_hits: ["malicious-cdn.example"], ip_reputation: "botnet node" },
    correlation_analysis: { linked_events: 6, kill_chain_stage: "Delivery" },
    detection: {
      label: "Web Shell Attempt",
      severity: "high",
      confidence: 0.89,
      threat_type: "Web Exploitation",
      reasoning: ["Suspicious upload path", "Exploit-style user agent", "Repetitive POST pattern"],
      triggered_engines: ["WAF", "UEBA"],
    },
    cis: { controls_impacted: ["CIS 16.6"], compliance_risk: "medium" },
    ai_analysis: {
      summary: "Likely web application exploitation attempt with persistence objectives.",
      one_liner: "AI detected a sophisticated web shell upload targeting your production API endpoint.",
      intent: "Web Application Compromise & Persistence",
      narrative:
        "Our AI security system has identified a targeted web application attack. An attacker used a well-known SQL injection scanner (sqlmap) to probe your web endpoint, then discovered an unprotected file upload functionality. The attack uploaded an ASPX web shell to /uploads/shell.aspx—a common persistence mechanism used by adversaries to maintain backdoor access. The detection was triggered by anomalous POST traffic patterns, a malicious user-agent signature, and the high entropy of the uploaded payload. This type of attack is frequently followed by reconnaissance and lateral movement attempts within your application infrastructure.",
      attack_vector:
        "Attack vector: Unauthenticated HTTP POST to application upload endpoint. The attacker identified a web application vulnerability (likely CVE-2024-XXXXX or similar), allowing arbitrary file upload without proper validation. The ASPX web shell provides remote code execution as the web server user.",
      impact: {
        confidentiality: "HIGH - Web shell enables data exfiltration",
        integrity: "HIGH - Attacker can modify application data",
        availability: "HIGH - Attacker can disrupt services",
      },
      next_steps: [
        "Immediately block the source IP at WAF policy level",
        "Restore web server from clean backup if web shell is confirmed",
        "Review web logs for reconnaissance activity post-upload",
        "Patch the upload vulnerability and validate file type validation",
      ],
    },
    cvss: { base_score: 8.2, severity: "high", vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L" },
    response: {
      priority: "P2",
      recommended_actions: ["Block IP", "Quarantine web node", "Review upload endpoints"],
      containment_steps: ["Rotate app secrets", "Inspect server uploads"],
    },
    final_report: { owner: "SOC Web Team", status: "Open" },
    dashboard: {
      alert_title: "Web Shell Upload Suspected",
      severity: "high",
      cvss_score: 8.2,
      source_ip: "203.0.113.41",
      affected_user: "anonymous",
    },
  }),
  network: normalizePipeline({
    event_id: "evt-net-001",
    raw_event: {
      timestamp: "2026-04-06T10:20:00Z",
      event_name: "Lateral Movement Beaconing",
      host: "jump-host-03",
      source_ip: "198.51.100.84",
      destination_ip: "10.10.4.21",
      protocol: "SMB",
    },
    ingestion: { source: "NetFlow", collector: "packet-agent", parsed_fields: 19 },
    feature_engineering: { east_west_spike: true, uncommon_smb_to_host: true, port_entropy: 0.76 },
    anomaly_detection: { model: "AutoEncoder-Net", anomaly_score: 0.93 },
    threat_analysis: { mitre_tactics: ["Lateral Movement", "Command and Control"], mitre_techniques: ["T1021.002", "T1071"] },
    ioc_enrichment: { ip_reputation: "known scanner", domain_hits: ["beacon-node.net"] },
    correlation_analysis: { linked_events: 14, kill_chain_stage: "Exploitation" },
    detection: {
      label: "Suspicious Network Beaconing",
      severity: "critical",
      confidence: 0.95,
      threat_type: "Lateral Movement",
      reasoning: ["Repeated SMB bursts", "Beacon cadence stable", "Source is risky"],
      triggered_engines: ["NetFlow ML", "Threat Intel", "Correlation Engine"],
    },
    cis: { controls_impacted: ["CIS 13.4", "CIS 12.3"], compliance_risk: "high" },
    ai_analysis: {
      summary: "Coordinated beaconing consistent with post-compromise movement.",
      one_liner: "AI detected coordinated lateral movement beaconing—a critical sign of post-exploit persistence.",
      intent: "Lateral Movement & Command and Control",
      narrative:
        "Our AI network threat detection system has identified a critical ongoing threat: coordinated SMB traffic between internal hosts showing characteristic command-and-control beaconing patterns. An internal system (jump-host-03) is communicating repeatedly with another internal host (10.10.4.21) in a stable, predictable cadence—hallmark of an attacker maintaining persistent control. The source host has been flagged by threat intelligence as a known scanner, and the destination IP is communicating with beacon-node.net. This pattern indicates the attacker has already compromised one system and is now actively moving laterally to extend their foothold. This is a critical escalation requiring immediate containment.",
      attack_vector:
        "Lateral movement via SMB (port 445): The attacker has already compromised jump-host-03 and is using it as a pivot point to scan and compromise additional hosts on the internal network. SMB is being used for reconnaissance, credential harvesting, and establishing secondary command-and-control channels.",
      impact: {
        confidentiality: "CRITICAL - Full network visibility to attacker",
        integrity: "CRITICAL - Attacker controls multiple systems",
        availability: "CRITICAL - Attacker can disable infrastructure",
      },
      next_steps: [
        "Immediately isolate jump-host-03 from the network",
        "Block all outbound traffic to beacon-node.net at the perimeter",
        "Quarantine the destination host (10.10.4.21) and run forensic imaging",
        "Hunt for all SMB lateral movement in the past 7 days",
        "Force password resets for all service accounts",
      ],
    },
    cvss: { base_score: 9.3, severity: "critical", vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" },
    response: {
      priority: "P1",
      recommended_actions: ["Segment host", "Block outbound beacon", "Preserve logs"],
      containment_steps: ["Hunt for SMB anomalies", "Disable suspicious accounts"],
    },
    final_report: { owner: "Network SOC", status: "Open" },
    dashboard: {
      alert_title: "Network Beaconing Detected",
      severity: "critical",
      cvss_score: 9.3,
      source_ip: "198.51.100.84",
      affected_user: "svc-sync",
    },
  }),
  iot: normalizePipeline({
    event_id: "evt-iot-001",
    raw_event: {
      timestamp: "2026-04-06T10:31:00Z",
      event_name: "IoT Camera Credential Abuse",
      host: "camera-warehouse-08",
      source_ip: "192.0.2.88",
      firmware: "2.4.1",
      login_attempts: 42,
    },
    ingestion: { source: "IoT Gateway", collector: "mqtt-forwarder", parsed_fields: 21 },
    feature_engineering: { default_credential_hit: true, firmware_outdated: true, auth_burst: true },
    anomaly_detection: { model: "IoT-RiskNet", anomaly_score: 0.87 },
    threat_analysis: { mitre_tactics: ["Initial Access", "Discovery"], mitre_techniques: ["T1078", "T1046"] },
    ioc_enrichment: { ip_reputation: "residential proxy", domain_hits: ["iot-control.example"] },
    correlation_analysis: { linked_events: 9, kill_chain_stage: "Reconnaissance" },
    detection: {
      label: "IoT Device Credential Abuse",
      severity: "medium",
      confidence: 0.84,
      threat_type: "IoT Compromise",
      reasoning: ["Repeated failed logins", "Outdated firmware", "Default credential usage"],
      triggered_engines: ["Gateway IDS", "IoT Risk Model"],
    },
    cis: { controls_impacted: ["CIS 5.1", "CIS 6.2"], compliance_risk: "medium" },
    ai_analysis: {
      summary: "Unauthorized access pattern against an exposed IoT endpoint.",
      one_liner: "AI detected a brute force attack targeting an outdated IoT camera with default credentials.",
      intent: "IoT Device Compromise & Internal Reconnaissance",
      narrative:
        "Our AI IoT security system has detected a concerning attack pattern targeting an internet-facing camera in your warehouse facility. An external attacker has launched 42 rapid login attempts against camera-warehouse-08, using default credential combinations (likely admin/admin, root/12345, etc.). This device is running outdated firmware (v2.4.1) with known authentication bypass vulnerabilities. While this particular device may not contain highly sensitive data, a successful compromise would give the attacker a foothold for reconnaissance of your facility, monitoring of physical infrastructure, and potential pivot points to connected operational technology networks. IoT devices are frequently overlooked in security monitoring and serve as easy entry points for attackers.",
      attack_vector:
        "Direct internet-facing IoT device: The camera is exposed on the public internet with default credentials and outdated firmware. An attacker discovered it via shodan.io or similar IoT scanning service and launched a dictionary attack using common default credentials.",
      impact: {
        confidentiality: "MEDIUM - Attacker gains physical facility visibility",
        integrity: "MEDIUM - Attacker can manipulate camera feeds",
        availability: "MEDIUM - Attacker can disable monitoring",
      },
      next_steps: [
        "Immediately change all default credentials on the camera",
        "Update camera firmware to the latest patched version",
        "Place the camera on an isolated OT network segment",
        "Remove the camera from direct internet exposure (use corporate VPN gateway)",
        "Review all other IoT devices for similar exposure",
      ],
    },
    cvss: { base_score: 6.8, severity: "medium", vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H" },
    response: {
      priority: "P3",
      recommended_actions: ["Reset device passwords", "Isolate camera VLAN", "Apply firmware update"],
      containment_steps: ["Audit device inventory", "Review gateway logs"],
    },
    final_report: { owner: "OT Security", status: "Open" },
    dashboard: {
      alert_title: "IoT Credential Abuse Detected",
      severity: "medium",
      cvss_score: 6.8,
      source_ip: "192.0.2.88",
      affected_user: "camera-warehouse-08",
    },
  }),
};

export function getScenarioPipeline(scenario: (typeof scenarioOptions)[number]["value"]) {
  return structuredClone(scenarioMap[scenario]);
}

export const STORAGE_KEY = "soc_uploaded_pipeline";
export const SIMULATION_EVENTS_KEY = "soc_simulated_events";

/**
 * Accumulate events from a simulation run into localStorage.
 * New events are MERGED with existing ones so history is retained across runs.
 */
export function saveSimulatedEvents(events: EventPipeline[]): void {
  if (typeof window === "undefined") return;
  try {
    // Load whatever is already stored and merge new events on top
    const existing = readSimulatedEventsMap();
    events.forEach((e) => { existing[e.event_id] = e; });
    localStorage.setItem(SIMULATION_EVENTS_KEY, JSON.stringify(existing));
  } catch { /* quota exceeded — ignore */ }
}

/** Wipe all accumulated simulation history from localStorage. */
export function clearSimulatedEvents(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(SIMULATION_EVENTS_KEY);
}

/** Read all simulated events from localStorage as a map keyed by event_id. */
export function readSimulatedEventsMap(): Record<string, EventPipeline> {
  if (typeof window === "undefined") return {};
  try {
    const raw = localStorage.getItem(SIMULATION_EVENTS_KEY);
    if (!raw) return {};
    return JSON.parse(raw) as Record<string, EventPipeline>;
  } catch {
    return {};
  }
}

/** Read all simulated events from localStorage as an ordered array. */
export function readSimulatedEvents(): EventPipeline[] {
  return Object.values(readSimulatedEventsMap()).map(normalizePipeline);
}

export function readStoredPipeline(): EventPipeline | null {
  if (typeof window === "undefined") return null;

  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return normalizePipeline(JSON.parse(raw));
  } catch {
    return null;
  }
}

export function getAllMockPipelines(): EventPipeline[] {
  return [
    ...mockPipelines.map((item) => structuredClone(item)),
    ...Object.values(scenarioMap).map((item) => structuredClone(item)),
  ];
}

export function getPipelineById(incidentId: string, uploadedPipeline?: EventPipeline | null): EventPipeline {
  if (uploadedPipeline?.event_id === incidentId) {
    return uploadedPipeline;
  }

  const matched = getAllMockPipelines().find((item) => item.event_id === incidentId);
  if (matched) return matched;

  // Check simulated events stored in localStorage
  const simMap = readSimulatedEventsMap();
  if (simMap[incidentId]) return normalizePipeline(simMap[incidentId]);

  if (uploadedPipeline) return uploadedPipeline;
  return createEmptyPipeline();
}
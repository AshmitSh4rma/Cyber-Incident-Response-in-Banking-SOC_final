/**
 * Severity presentation — one definition, used everywhere.
 *
 * Severity is a STATUS scale: a small fixed set with reserved meaning, not a
 * categorical palette. Two consequences the whole app follows:
 *
 *  1. Red / orange / yellow sit close in hue by construction, so they cannot be
 *     separated by colour alone under colour-vision deficiency. Every severity
 *     indicator therefore carries a TEXT LABEL. Colour is a second channel, never
 *     the only one. `SeverityChip` enforces this so a caller cannot forget.
 *  2. These hexes are fixed and measured (contrast noted in globals.css). They are
 *     Tailwind theme colours (`sev-critical` …), not `red-400` — Tailwind's ramp
 *     is a different, unmeasured set.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "benign";

export function normalizeSeverity(value: unknown): Severity {
  const v = String(value ?? "low").toLowerCase();
  if (v === "critical" || v === "high" || v === "medium" || v === "low" || v === "benign") return v;
  return "low";
}

type Tone = {
  /** Filled chip for the severity badge. */
  chip: string;
  /** The dot / rail / mark colour. */
  mark: string;
  /** Text-only emphasis. Use sparingly — values normally wear text tokens. */
  text: string;
  /** Meter track: a darker step of the mark's own hue, never grey. */
  track: string;
  /** Card border tint. */
  border: string;
  /** Rank, for sorting a queue worst-first. */
  rank: number;
};

export const SEVERITY_TONE: Record<Severity, Tone> = {
  critical: {
    chip: "border-sev-critical/40 bg-sev-critical/15 text-sev-critical",
    mark: "bg-sev-critical",
    text: "text-sev-critical",
    track: "bg-track-critical",
    border: "border-sev-critical/30",
    rank: 4,
  },
  high: {
    chip: "border-sev-high/40 bg-sev-high/15 text-sev-high",
    mark: "bg-sev-high",
    text: "text-sev-high",
    track: "bg-track-high",
    border: "border-sev-high/25",
    rank: 3,
  },
  medium: {
    chip: "border-sev-medium/35 bg-sev-medium/12 text-sev-medium",
    mark: "bg-sev-medium",
    text: "text-sev-medium",
    track: "bg-track-medium",
    border: "border-rule",
    rank: 2,
  },
  low: {
    chip: "border-sev-low/35 bg-sev-low/12 text-sev-low",
    mark: "bg-sev-low",
    text: "text-sev-low",
    track: "bg-track-low",
    border: "border-rule",
    rank: 1,
  },
  benign: {
    chip: "border-sev-benign/35 bg-sev-benign/12 text-sev-benign",
    mark: "bg-sev-benign",
    text: "text-sev-benign",
    track: "bg-track-neutral",
    border: "border-rule-soft",
    rank: 0,
  },
};

export function severityTone(value: unknown): Tone {
  return SEVERITY_TONE[normalizeSeverity(value)];
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "benign"];

/** Detection verdicts. Also a status scale — always labelled. */
export function verdictTone(label: unknown): string {
  const v = String(label ?? "").toLowerCase();
  if (v === "malicious") return "border-sev-critical/40 bg-sev-critical/15 text-sev-critical";
  if (v === "suspicious") return "border-sev-high/35 bg-sev-high/12 text-sev-high";
  if (v === "suppressed") return "border-rule bg-raised text-faint";
  return "border-sev-benign/35 bg-sev-benign/12 text-sev-benign";
}

/**
 * The 15 ATT&CK Enterprise tactics in lifecycle order, mirroring
 * layer_2_detection/mitre_mapper.py.
 */
export const ATTACK_TACTICS: { id: string; name: string; short: string }[] = [
  { id: "TA0043", name: "Reconnaissance", short: "Recon" },
  { id: "TA0042", name: "Resource Development", short: "ResDev" },
  { id: "TA0001", name: "Initial Access", short: "Access" },
  { id: "TA0002", name: "Execution", short: "Exec" },
  { id: "TA0003", name: "Persistence", short: "Persist" },
  { id: "TA0004", name: "Privilege Escalation", short: "PrivEsc" },
  { id: "TA0005", name: "Stealth", short: "Stealth" },
  { id: "TA0112", name: "Defense Impairment", short: "DefImp" },
  { id: "TA0006", name: "Credential Access", short: "Creds" },
  { id: "TA0007", name: "Discovery", short: "Discover" },
  { id: "TA0008", name: "Lateral Movement", short: "Lateral" },
  { id: "TA0009", name: "Collection", short: "Collect" },
  { id: "TA0011", name: "Command and Control", short: "C2" },
  { id: "TA0010", name: "Exfiltration", short: "Exfil" },
  { id: "TA0040", name: "Impact", short: "Impact" },
];

/**
 * How deep into the lifecycle a stage sits, expressed on the severity scale so
 * the whole app reads one ramp. Reaching Exfiltration is critical; a scan is not.
 */
export function stageSeverity(order: number): Severity {
  if (order >= 14) return "critical";
  if (order >= 11) return "high";
  if (order >= 6) return "medium";
  if (order >= 1) return "low";
  return "benign";
}

/** Notification clock states — status, always labelled. */
export function clockTone(state: string): { chip: string; mark: string; label: string } {
  if (state === "overdue")
    return {
      chip: "border-sev-critical/40 bg-sev-critical/15 text-sev-critical",
      mark: "bg-sev-critical",
      label: "Overdue",
    };
  if (state === "due_soon")
    return {
      chip: "border-sev-high/40 bg-sev-high/15 text-sev-high",
      mark: "bg-sev-high",
      label: "Due soon",
    };
  return {
    chip: "border-sev-benign/35 bg-sev-benign/12 text-sev-benign",
    mark: "bg-sev-benign",
    label: "On track",
  };
}

export function formatTimestamp(value: unknown): string {
  const raw = String(value ?? "").trim();
  if (!raw) return "—";
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return raw;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Compact a count for a stat tile: 1,284 / 12.9K / 4.2M. */
export function compact(value: unknown): string {
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (Math.abs(n) >= 10_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

export function formatBytes(value: unknown): string {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

/** 'in 3h 12m' / 'overdue by 2h 4m' — from a signed seconds value. */
export function formatRemaining(seconds: number): string {
  const overdue = seconds < 0;
  const s = Math.abs(Math.round(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  let text: string;
  if (h >= 24) text = `${Math.floor(h / 24)}d ${h % 24}h`;
  else if (h) text = `${h}h ${m}m`;
  else text = `${m}m`;
  return overdue ? `overdue by ${text}` : text;
}

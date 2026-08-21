/**
 * Severity and stage presentation.
 *
 * Single source of truth so the ramp means the same thing on every screen — a
 * dashboard where "high" is orange in one card and red in another trains the
 * analyst to stop trusting colour.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "benign";

export function normalizeSeverity(value: unknown): Severity {
  const v = String(value ?? "low").toLowerCase();
  if (v === "critical" || v === "high" || v === "medium" || v === "low" || v === "benign") return v;
  return "low";
}

type Tone = {
  /** filled chip, for the primary severity badge */
  chip: string;
  /** the dot / rail colour */
  dot: string;
  /** text-only, for inline emphasis */
  text: string;
  /** left accent rail on a card */
  rail: string;
  /** subtle card border tint */
  border: string;
};

export const SEVERITY_TONE: Record<Severity, Tone> = {
  critical: {
    chip: "border-red-500/40 bg-red-500/12 text-red-300",
    dot: "bg-red-400",
    text: "text-red-300",
    rail: "bg-red-500",
    border: "border-red-900/40",
  },
  high: {
    chip: "border-orange-500/40 bg-orange-500/12 text-orange-300",
    dot: "bg-orange-400",
    text: "text-orange-300",
    rail: "bg-orange-500",
    border: "border-orange-900/35",
  },
  medium: {
    chip: "border-yellow-500/35 bg-yellow-500/10 text-yellow-300",
    dot: "bg-yellow-400",
    text: "text-yellow-300",
    rail: "bg-yellow-500",
    border: "border-slate-700/60",
  },
  low: {
    chip: "border-sky-500/35 bg-sky-500/10 text-sky-300",
    dot: "bg-sky-400",
    text: "text-sky-300",
    rail: "bg-sky-500",
    border: "border-slate-700/60",
  },
  benign: {
    chip: "border-emerald-600/35 bg-emerald-600/10 text-emerald-300",
    dot: "bg-emerald-400",
    text: "text-emerald-300",
    rail: "bg-emerald-600",
    border: "border-slate-800/60",
  },
};

export function severityTone(value: unknown): Tone {
  return SEVERITY_TONE[normalizeSeverity(value)];
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "benign"];

/** Verdict labels the detection layer emits. */
export function verdictTone(label: unknown): string {
  const v = String(label ?? "").toLowerCase();
  if (v === "malicious") return "border-red-500/40 bg-red-500/12 text-red-300";
  if (v === "suspicious") return "border-orange-500/35 bg-orange-500/10 text-orange-300";
  if (v === "suppressed") return "border-slate-600/50 bg-slate-700/20 text-slate-400";
  return "border-emerald-600/35 bg-emerald-600/10 text-emerald-300";
}

/**
 * The 15 ATT&CK Enterprise tactics in lifecycle order, mirroring
 * layer_2_detection/mitre_mapper.py. Used to render the kill-chain rail so a
 * campaign's progress is visible against the whole lifecycle, not just its own
 * stages.
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

/** Colour a stage by how deep into the lifecycle it is. */
export function stageTone(order: number): string {
  if (order >= 14) return "text-red-300";
  if (order >= 11) return "text-orange-300";
  if (order >= 6) return "text-yellow-300";
  return "text-sky-300";
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
    second: "2-digit",
  });
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

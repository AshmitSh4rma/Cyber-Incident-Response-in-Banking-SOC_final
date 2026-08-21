"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { EventPipeline, readSimulatedEvents, clearSimulatedEvents } from "@/lib/mockData";
import { severityTone } from "@/lib/utils";
import { usePipeline } from "@/hooks/usePipeline";
import {
  AlertOctagon,
  Search,
  Clock,
  User,
  Server,
  Activity,
  ExternalLink,
  Brain,
  ChevronDown,
  ChevronUp,
  Play,
  Trash2,
  Terminal,
  Sparkles,
  ShieldCheck,
  Globe,
  Database,
  CheckCircle2,
  Lock,
  LockOpen,
  Zap,
  GitBranch,
} from "lucide-react";
import MetricsHeader from "@/components/soc/MetricsHeader";
import TemporalSparkline from "@/components/visuals/TemporalSparkline";
import EventFrequencyBars from "@/components/visuals/EventFrequencyBars";

type JsonEvent = Record<string, any>;

/* ─── helpers ───────────────────────────────────────────────────── */
function normalizeSeverity(value: string | undefined | null): string {
  const n = String(value ?? "low").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(n) ? n : "low";
}

function normalizeEventToPipeline(event: JsonEvent, index: number): EventPipeline {
  const severity = normalizeSeverity(event?.detection?.severity || event?.dashboard?.severity);
  const eventId = event?.event_id || event?.incident_id || `evt-json-${index + 1}`;
  const alertTitle =
    event?.dashboard?.alert_title ||
    event?.summary ||
    event?.ai_analysis?.intent ||
    event?.detection?.threat_type?.replaceAll("_", " ") ||
    "Unknown Alert";
  const affectedUser =
    event?.dashboard?.affected_user || event?.raw_event?.affected_user || event?.raw_event?.user || "anonymous";
  const sourceIp =
    event?.dashboard?.source_ip || event?.raw_event?.source_ip || event?.raw_event?.src_ip || "N/A";
  const aiSummary =
    event?.ai_analysis?.one_liner ||
    event?.ai_analysis?.summary ||
    event?.ai_analysis?.narrative ||
    event?.detection?.reasoning?.[0] ||
    event?.summary ||
    "Investigation context available in incident workspace.";
  const status = String(event?.final_report?.status ?? event?.status ?? "open").toLowerCase();
  return {
    ...(event as EventPipeline),
    event_id: eventId,
    dashboard: { ...(event?.dashboard ?? {}), alert_title: alertTitle, severity, affected_user: affectedUser, source_ip: sourceIp },
    ai_analysis: { ...(event?.ai_analysis ?? {}), one_liner: event?.ai_analysis?.one_liner ?? aiSummary, summary: event?.ai_analysis?.summary ?? aiSummary },
    final_report: { ...(event?.final_report ?? {}), status },
  };
}

const SEVERITY_CONFIG: Record<string, { dot: string; badge: string; glow: string; border: string }> = {
  critical: { dot: "bg-red-500", badge: "bg-red-500/10 text-red-400 border-red-500/30", glow: "shadow-[0_0_0_1px_rgba(239,68,68,0.15)]", border: "border-red-900/40" },
  high:     { dot: "bg-orange-500", badge: "bg-orange-500/10 text-orange-400 border-orange-500/30", glow: "shadow-[0_0_0_1px_rgba(249,115,22,0.12)]", border: "border-orange-900/40" },
  medium:   { dot: "bg-yellow-500", badge: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30", glow: "", border: "border-slate-700/60" },
  low:      { dot: "bg-sky-500", badge: "bg-sky-500/10 text-sky-400 border-sky-500/30", glow: "", border: "border-slate-700/60" },
};

/* ─── main component ─────────────────────────────────────────────── */
export default function DashboardPage() {
  const uploadedPipeline = usePipeline();
  const [jsonPipelines, setJsonPipelines] = useState<EventPipeline[]>([]);
  const [simPipelines, setSimPipelines] = useState<EventPipeline[]>([]);
  const [jsonLoaded, setJsonLoaded] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [showNoise, setShowNoise] = useState(false);
  const [expandedIncidents, setExpandedIncidents] = useState<Record<string, boolean>>({});
  const [localStatus, setLocalStatus] = useState<Record<string, string>>({});

  const loadSims = async () => {
    const sims = readSimulatedEvents();
    if (sims.length > 0) {
      try {
        await fetch("/api/simulate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ events: sims }),
        });
      } catch (err) {
        console.error("Error syncing simulated events:", err);
      }
    }
    sims.sort((a, b) => ((b as any)?.raw_event?.timestamp ?? "").localeCompare((a as any)?.raw_event?.timestamp ?? ""));
    setSimPipelines(sims);
  };

  useEffect(() => { loadSims(); }, []);

  useEffect(() => {
    let isMounted = true;
    async function load() {
      try {
        const res = await fetch("/api/incidents", { cache: "no-store" });
        if (!res.ok) throw new Error(`${res.status}`);
        const data = await res.json();
        if (!isMounted) return;
        const raw = Array.isArray(data) ? data : Array.isArray(data?.events) ? data.events : [];
        setJsonPipelines(raw.map((e: JsonEvent, i: number) => normalizeEventToPipeline(e, i)));
      } catch { if (isMounted) setJsonPipelines([]); }
      finally { if (isMounted) setJsonLoaded(true); }
    }
    load();
    return () => { isMounted = false; };
  }, []);

  const handleClearHistory = async () => {
    try { await fetch("/api/incidents", { method: "DELETE" }); } catch {}
    clearSimulatedEvents();
    setSimPipelines([]);
    setJsonPipelines([]);
  };

  const toggleExpand = (id: string) =>
    setExpandedIncidents((p) => ({ ...p, [id]: !p[id] }));

  const handleToggleStatus = async (e: React.MouseEvent, id: string, cur: string) => {
    e.stopPropagation();
    const next = cur === "closed" ? "open" : "closed";
    setLocalStatus((p) => ({ ...p, [id]: next }));
    try {
      await fetch(`/api/incidents/${id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: next === "closed" ? "close" : "open" }),
      });
    } catch {
      setLocalStatus((p) => ({ ...p, [id]: cur }));
    }
  };

  const incidents = useMemo(() => {
    // Live backend first, then any locally-held simulation results. Deliberately
    // NO mock fallback: a security console that invents alerts to look busy
    // teaches the analyst to distrust everything on the screen.
    const base = jsonPipelines.length > 0 ? jsonPipelines : simPipelines;
    let list = base;
    if (uploadedPipeline) list = [uploadedPipeline, ...base.filter((i) => i.event_id !== uploadedPipeline.event_id)];
    return list;
  }, [uploadedPipeline, jsonPipelines, simPipelines]);

  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      // Benign and analyst-suppressed events are kept in the store (and counted
      // in the metrics header) but stay out of the working queue unless the
      // analyst explicitly filters for them.
      const verdict = String(inc.detection?.label ?? "").toLowerCase();
      if (!showNoise && (verdict === "benign" || verdict === "suppressed")) return false;
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !q ||
        (inc.dashboard?.alert_title ?? "").toLowerCase().includes(q) ||
        (inc.dashboard?.source_ip ?? "").toLowerCase().includes(q) ||
        (inc.dashboard?.affected_user ?? "").toLowerCase().includes(q) ||
        (inc.raw_event?.affected_host ?? inc.raw_event?.host ?? "").toLowerCase().includes(q) ||
        (inc.detection?.threat_type ?? "").toLowerCase().includes(q);
      const sev = String(inc.dashboard?.severity ?? "low").toLowerCase();
      const matchesSeverity = severityFilter === "all" || sev === severityFilter;
      const status = localStatus[inc.event_id] ?? String(inc.final_report?.status ?? "open").toLowerCase();
      const matchesStatus =
        statusFilter === "all" ||
        (statusFilter === "open" && status !== "closed") ||
        (statusFilter === "closed" && status === "closed");
      return matchesSearch && matchesSeverity && matchesStatus;
    });
  }, [incidents, searchQuery, severityFilter, statusFilter, localStatus, showNoise]);

  const summary = useMemo(() => {
    const total = incidents.length;
    const critical = incidents.filter((i) => String(i.dashboard?.severity ?? "low").toLowerCase() === "critical").length;
    const high = incidents.filter((i) => String(i.dashboard?.severity ?? "low").toLowerCase() === "high").length;
    const active = incidents.filter((i) => (localStatus[i.event_id] ?? String(i.final_report?.status ?? "open").toLowerCase()) !== "closed").length;
    const ips = new Set(incidents.map((i) => i.dashboard?.source_ip ?? i.raw_event?.source_ip).filter(Boolean));
    return { total, critical, high, active, ips: ips.size };
  }, [incidents, localStatus]);

  const frequencyMetrics = useMemo(() => {
    const c = { auth: 0, network: 0, web: 0, endpoint: 0 };
    incidents.forEach((i) => {
      const t = String(i.raw_event?.log_type ?? i.ingestion?.log_family ?? "network").toLowerCase();
      if (t.includes("auth") || t.includes("login")) c.auth++;
      else if (t.includes("web") || t.includes("http")) c.web++;
      else if (t.includes("endpoint") || t.includes("process") || t.includes("file")) c.endpoint++;
      else c.network++;
    });
    const max = Math.max(c.auth, c.network, c.web, c.endpoint, 1);
    return [
      { label: "Authentication Logs", value: c.auth, max, color: "bg-blue-500", icon: "🔐" },
      { label: "Network Telemetry", value: c.network, max, color: "bg-cyan-500", icon: "🌐" },
      { label: "Web Server Requests", value: c.web, max, color: "bg-purple-500", icon: "🌐" },
      { label: "Endpoint Process Traces", value: c.endpoint, max, color: "bg-orange-500", icon: "🖥️" },
    ];
  }, [incidents]);

  return (
    <motion.div
      className="min-h-screen space-y-6 px-0"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
    >
      {/* ── Value metrics, computed from stored state ─────────────── */}
      <MetricsHeader />

      {/* ── Header ────────────────────────────────────────────────── */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-800/60 bg-gradient-to-br from-slate-900 via-slate-900/95 to-slate-950 p-6 shadow-2xl">
        {/* Subtle top accent line */}
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-500/40 to-transparent" />
        {/* Ambient glow */}
        <div className="pointer-events-none absolute -top-20 left-1/2 h-40 w-[600px] -translate-x-1/2 rounded-full bg-cyan-500/5 blur-3xl" />

        <div className="relative flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-400 opacity-60" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-cyan-400" />
              </span>
              <span className="text-[11px] font-semibold uppercase tracking-[0.25em] text-cyan-400/80">
                SENTRA · Cyber Operations
              </span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-white">
              Active Incident Command Center
            </h1>
            <p className="mt-1 max-w-lg text-xs leading-relaxed text-slate-400">
              Multi-layered threat ingestion · ML detection · MITRE mapping · Automated response
            </p>
          </div>

          <div className="flex items-center gap-2">
            {simPipelines.length > 0 && (
              <button
                id="btn-clear-history"
                onClick={handleClearHistory}
                className="inline-flex items-center gap-1.5 rounded-lg border border-red-900/50 bg-red-950/20 px-3 py-1.5 text-xs font-semibold text-red-400 transition hover:bg-red-900/30"
              >
                <Trash2 className="h-3.5 w-3.5" /> Clear History
              </button>
            )}
            <Link href="/upload">
              <button id="btn-upload-lab" className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 px-4 py-2 text-xs font-bold text-slate-950 shadow-[0_0_20px_rgba(6,182,212,0.3)] transition hover:bg-cyan-400 active:scale-95">
                <Play className="h-3.5 w-3.5 fill-current" /> Simulation Lab
              </button>
            </Link>
          </div>
        </div>
      </div>

      {/* ── Metric Cards ──────────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Total Incidents" value={summary.total} sub="Accumulated history" icon={<Database className="h-4 w-4" />} color="slate" />
        <StatCard label="Critical Threats" value={summary.critical} sub="Immediate action required" icon={<AlertOctagon className="h-4 w-4" />} color="red" />
        <StatCard label="Unique Source IPs" value={summary.ips} sub="Offender addresses flagged" icon={<Globe className="h-4 w-4" />} color="orange" />
        <StatCard label="Pending Reviews" value={summary.active} sub="Awaiting analyst action" icon={<Activity className="h-4 w-4" />} color="cyan" />
      </div>

      {/* ── Main Grid ─────────────────────────────────────────────── */}
      <div className="grid gap-6 lg:grid-cols-3">

        {/* Left: Incident Queue */}
        <section className="lg:col-span-2 space-y-4">

          {/* Search + Filter Bar */}
          <div className="flex flex-col gap-3 rounded-xl border border-slate-800/60 bg-slate-900/50 p-4 sm:flex-row sm:items-center sm:justify-between">
            {/* Search */}
            <div className="relative w-full sm:max-w-xs">
              <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search by IP, user, host, threat…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full rounded-lg border border-slate-700/60 bg-slate-950 py-2 pl-8.5 pr-3 text-xs text-slate-100 placeholder-slate-500 outline-none ring-0 transition focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30"
              />
            </div>

            {/* Filter pills */}
            <div className="flex flex-wrap gap-2">
              <FilterPillGroup
                options={["all", "critical", "high", "medium", "low"]}
                active={severityFilter}
                onChange={setSeverityFilter}
              />
              <FilterPillGroup
                options={["all", "open", "closed"]}
                active={statusFilter}
                onChange={setStatusFilter}
              />
              <button
                onClick={() => setShowNoise((v) => !v)}
                title="Benign and analyst-suppressed events are excluded from the working queue by default"
                className={[
                  "rounded-lg border px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-wider transition",
                  showNoise
                    ? "border-slate-600 bg-slate-700/50 text-slate-200"
                    : "border-slate-800/60 bg-slate-950/60 text-slate-500 hover:text-slate-300",
                ].join(" ")}
              >
                {showNoise ? "Hiding nothing" : "Filtered"}
              </button>
            </div>
          </div>

          {/* Result count + sync status */}
          <div className="flex items-center justify-between px-1 text-[11px] text-slate-500">
            <span>
              Showing <span className="font-semibold text-slate-300">{filteredIncidents.length}</span> of {incidents.length} incidents
            </span>
            {jsonLoaded ? (
              <span className="flex items-center gap-1.5 text-emerald-500/80">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                Pipeline sync online
              </span>
            ) : (
              <span className="text-slate-600">Connecting…</span>
            )}
          </div>

          {/* Cards */}
          {filteredIncidents.length === 0 ? (
            <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 bg-slate-950/40 py-16 text-center">
              <ShieldCheck className="mb-3 h-10 w-10 text-slate-700" />
              <p className="text-sm font-semibold text-slate-300">All Clear in Banking Operations</p>
              <p className="mt-1 max-w-xs text-xs text-slate-500">
                No active incidents match the current filters. Run the Simulation Lab to generate telemetry.
              </p>
            </div>
          ) : (
            <AnimatePresence>
              <div className="space-y-3">
                {filteredIncidents.map((incident) => {
                  const id = incident.event_id;
                  const isExpanded = !!expandedIncidents[id];
                  const severity = String(incident.dashboard?.severity ?? incident.detection?.severity ?? "low").toLowerCase();
                  const cvss = Number(incident.cvss?.base_score ?? incident.dashboard?.cvss_score ?? 0);
                  const cfg = SEVERITY_CONFIG[severity] ?? SEVERITY_CONFIG.low;
                  const incidentStatus = localStatus[id] ?? String(incident.final_report?.status ?? "open").toLowerCase();
                  const isClosed = incidentStatus === "closed";

                  // AI Triage data
                  const aiIntent = incident.ai_analysis?.intent || incident.detection?.threat_type?.replaceAll("_", " ") || "Unknown Intent";
                  const aiConfidence = Math.round((incident.detection?.confidence ?? incident.ai_analysis?.confidence ?? 0.75) * 100);
                  const aiNarrative = incident.ai_analysis?.one_liner || incident.ai_analysis?.summary || "AI analysis complete.";
                  const aiConf = incident.ai_analysis?.impact?.confidentiality?.split(" ")[0] || "HIGH";
                  const aiInteg = incident.ai_analysis?.impact?.integrity?.split(" ")[0] || "HIGH";
                  const aiAvail = incident.ai_analysis?.impact?.availability?.split(" ")[0] || "MED";
                  const confidenceColor = aiConfidence >= 85 ? "bg-red-500" : aiConfidence >= 65 ? "bg-orange-500" : "bg-yellow-500";
                  const confidenceText = aiConfidence >= 85 ? "text-red-400" : aiConfidence >= 65 ? "text-orange-400" : "text-yellow-400";

                  return (
                    <motion.div
                      key={id}
                      layoutId={`card-${id}`}
                      initial={{ opacity: 0, y: 12 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, scale: 0.98 }}
                      transition={{ duration: 0.25 }}
                      className={[
                        "group relative overflow-hidden rounded-xl border transition-all duration-300",
                        isClosed
                          ? "border-slate-800/40 bg-slate-900/20 opacity-55"
                          : isExpanded
                            ? "border-slate-600/60 bg-slate-900/90 shadow-xl"
                            : `${cfg.border} bg-slate-900/60 hover:bg-slate-900/90 ${cfg.glow}`,
                      ].join(" ")}
                    >
                      {/* Severity left accent bar */}
                      {!isClosed && (
                        <div className={`absolute left-0 top-0 h-full w-0.5 ${cfg.dot} opacity-70`} />
                      )}

                      {/* ── Card Header (always visible) ── */}
                      <div
                        className="flex cursor-pointer items-start gap-4 px-5 pt-4 pb-3"
                        onClick={() => toggleExpand(id)}
                      >
                        {/* Severity dot */}
                        <div className="mt-1 shrink-0">
                          <div className={`h-2 w-2 rounded-full ${cfg.dot} ${!isClosed && severity === "critical" ? "animate-pulse" : ""}`} />
                        </div>

                        {/* Main text block */}
                        <div className="flex-1 min-w-0 space-y-1">
                          {/* Badges row */}
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className={`inline-flex items-center rounded px-2 py-0.5 text-[9px] font-extrabold uppercase tracking-widest border ${cfg.badge}`}>
                              {severity}
                            </span>
                            <span className="inline-flex items-center rounded border border-slate-700/60 bg-slate-800/60 px-2 py-0.5 text-[9px] font-bold text-sky-400">
                              {incident.response?.priority || "P3"}
                            </span>
                            {isClosed && (
                              <span className="inline-flex items-center gap-1 rounded border border-emerald-800/50 bg-emerald-950/40 px-2 py-0.5 text-[9px] font-bold text-emerald-400">
                                <CheckCircle2 className="h-2.5 w-2.5" /> Reviewed
                              </span>
                            )}
                            <span className="font-mono text-[10px] text-slate-600">{id}</span>
                            {incident.campaign?.campaign_id && (
                              <Link
                                href={`/campaigns/${incident.campaign.campaign_id}`}
                                onClick={(e) => e.stopPropagation()}
                                className="inline-flex items-center gap-1 rounded border border-red-900/50 bg-red-950/25 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-red-300 transition hover:bg-red-950/50"
                                title={`Part of ${incident.campaign.name} — ${incident.campaign.incident_count} correlated alerts reaching ${incident.campaign.furthest_stage}`}
                              >
                                <GitBranch className="h-2.5 w-2.5" />
                                {incident.campaign.campaign_id}
                              </Link>
                            )}
                            {incident.mitre_attack?.primary?.technique_id && (
                              <span className="font-mono rounded border border-cyan-900/50 bg-cyan-950/25 px-1.5 py-0.5 text-[9px] text-cyan-300">
                                {incident.mitre_attack.primary.technique_id}
                              </span>
                            )}
                            {incident.response?.requires_human_approval && (
                              <span
                                className="rounded border border-amber-800/50 bg-amber-950/30 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-amber-400"
                                title={`${incident.response.awaiting_approval} containment action(s) need analyst approval`}
                              >
                                approval
                              </span>
                            )}
                          </div>

                          {/* Title */}
                          <h3 className="text-sm font-bold leading-snug tracking-tight text-slate-100">
                            {incident.dashboard?.alert_title || "Security Incident Trigger"}
                          </h3>

                          {/* Meta row */}
                          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-500">
                            <span className="flex items-center gap-1">
                              <User className="h-3 w-3" />
                              <span className="text-slate-300">{incident.dashboard?.affected_user || "anonymous"}</span>
                            </span>
                            <span className="flex items-center gap-1">
                              <Server className="h-3 w-3" />
                              <span className="text-slate-300">{incident.raw_event?.affected_host || incident.raw_event?.host || "workstation"}</span>
                            </span>
                            <span className="flex items-center gap-1">
                              <Globe className="h-3 w-3" />
                              <span className="font-mono text-slate-300">{incident.dashboard?.source_ip || "N/A"}</span>
                            </span>
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {incident.raw_event?.timestamp ? new Date(incident.raw_event.timestamp).toLocaleTimeString() : "Recent"}
                            </span>
                          </div>


                        </div>

                        {/* Right: CVSS + actions */}
                        <div className="flex shrink-0 items-center gap-2">
                          {/* CVSS pill */}
                          <div className="text-right">
                            <p className="text-[9px] font-bold uppercase tracking-wider text-slate-600">CVSS</p>
                            <p className={`text-lg font-black leading-none ${
                              cvss >= 9 ? "text-red-400" : cvss >= 7 ? "text-orange-400" : cvss >= 4 ? "text-yellow-400" : "text-sky-400"
                            }`}>
                              {cvss.toFixed(1)}
                            </p>
                          </div>

                          {/* Close/Reopen icon button */}
                          <button
                            onClick={(e) => handleToggleStatus(e, id, incidentStatus)}
                            title={isClosed ? "Reopen incident" : "Mark as reviewed & close"}
                            className={`rounded-lg border p-1.5 transition-all ${
                              isClosed
                                ? "border-emerald-700/50 bg-emerald-950/30 text-emerald-400 hover:bg-emerald-900/40"
                                : "border-slate-700/60 bg-slate-800/40 text-slate-500 hover:border-emerald-700/60 hover:text-emerald-400"
                            }`}
                          >
                            {isClosed ? <LockOpen className="h-3.5 w-3.5" /> : <Lock className="h-3.5 w-3.5" />}
                          </button>

                          {/* Expand toggle */}
                          <button className="rounded-lg border border-slate-700/60 bg-slate-800/40 p-1.5 text-slate-500 transition hover:text-slate-200">
                            {isExpanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                          </button>
                        </div>
                      </div>

                      {/* ── AI Triage Strip (collapsed only) ── */}
                      {!isExpanded && !isClosed && (
                        <div className="mx-5 mb-3 rounded-lg border border-pink-900/30 bg-gradient-to-r from-pink-950/30 via-slate-900/60 to-slate-900/40 p-3">
                          {/* Header row */}
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-1.5">
                              <Zap className="h-3 w-3 text-pink-400" />
                              <span className="text-[9px] font-extrabold uppercase tracking-[0.18em] text-pink-400">SENTRA AI Triage</span>
                            </div>
                            <div className="flex items-center gap-1">
                              <span className={`text-[10px] font-black ${confidenceText}`}>{aiConfidence}%</span>
                              <span className="text-[9px] text-slate-600">confidence</span>
                            </div>
                          </div>

                          <div className="grid grid-cols-2 gap-3">
                            {/* Left: intent + narrative */}
                            <div className="col-span-2 sm:col-span-1 space-y-1.5">
                              <div className="inline-flex items-center rounded border border-pink-800/40 bg-pink-950/40 px-2 py-0.5 text-[9px] font-bold text-pink-300 max-w-full">
                                <span className="truncate">{aiIntent}</span>
                              </div>
                              <p className="text-[10px] leading-relaxed text-slate-400 line-clamp-2">{aiNarrative}</p>
                            </div>

                            {/* Right: CIA impact + confidence bar */}
                            <div className="col-span-2 sm:col-span-1 space-y-2">
                              <div className="flex gap-1.5">
                                {[
                                  { k: "C", v: aiConf,  title: "Confidentiality" },
                                  { k: "I", v: aiInteg, title: "Integrity" },
                                  { k: "A", v: aiAvail, title: "Availability" },
                                ].map(({ k, v, title }) => (
                                  <div key={k} title={title} className="flex-1 rounded border border-slate-800/60 bg-slate-900/80 py-1 text-center">
                                    <p className="text-[8px] font-bold text-slate-600">{k}</p>
                                    <p className={`text-[9px] font-extrabold ${
                                      v === "HIGH" || v === "CRITICAL" ? "text-red-400" : v === "MEDIUM" || v === "MED" ? "text-yellow-400" : "text-sky-400"
                                    }`}>{v}</p>
                                  </div>
                                ))}
                              </div>
                              {/* Confidence bar */}
                              <div className="space-y-0.5">
                                <div className="h-1 w-full overflow-hidden rounded-full bg-slate-800/80">
                                  <div className={`h-full rounded-full ${confidenceColor} transition-all duration-700`} style={{ width: `${aiConfidence}%` }} />
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* ── Pipeline Layer Dots (collapsed only) ── */}
                      {!isExpanded && (
                        <div className="flex items-center justify-between border-t border-slate-800/60 px-5 py-2.5">
                          <div className="flex items-center gap-1">
                            <span className="mr-1.5 text-[9px] font-bold uppercase tracking-wider text-slate-600">Layers:</span>
                            <PipelineDot label="L1 Ingestion"  status={incident.ingestion ? "done" : "idle"}          color="#06b6d4" />
                            <PipelineDot label="L2 Anomaly"   status={incident.anomaly_detection ? "done" : "idle"}   color="#8b5cf6" />
                            <PipelineDot label="L3 CIS"       status={incident.cis ? "done" : "idle"}                 color="#f59e0b" />
                            <PipelineDot label="L4 AI"        status={incident.ai_analysis ? "done" : "idle"}         color="#ec4899" />
                            <PipelineDot label="L5 CVSS"      status={incident.cvss ? "done" : "idle"}                color="#14b8a6" />
                            <PipelineDot label="L6 Response"  status={incident.response ? "done" : "idle"}            color="#22c55e" />
                          </div>

                          <div className="flex items-center gap-4">
                            <button
                              onClick={(e) => handleToggleStatus(e, id, incidentStatus)}
                              className={`flex items-center gap-1 text-[10px] font-semibold transition ${
                                isClosed ? "text-emerald-400 hover:text-emerald-300" : "text-slate-500 hover:text-emerald-400"
                              }`}
                            >
                              {isClosed ? <><LockOpen className="h-3 w-3" /> Reopen</> : <><Lock className="h-3 w-3" /> Close Log</>}
                            </button>
                            <Link href={`/incident/${id}`}>
                              <span className="flex items-center gap-1 text-[10px] font-semibold text-sky-500 hover:text-sky-400 transition">
                                Workspace <ExternalLink className="h-3 w-3" />
                              </span>
                            </Link>
                          </div>
                        </div>
                      )}

                      {/* ── Expanded Detail Panel ── */}
                      <AnimatePresence>
                        {isExpanded && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.3, ease: "easeInOut" }}
                            className="overflow-hidden border-t border-slate-800/60"
                          >
                            <div className="p-5 space-y-5">
                              {/* Three-column detail grid */}
                              <div className="grid gap-4 md:grid-cols-3">
                                {/* L1 + L2 */}
                                <DetailPanel title="Telemetry & Anomalies" titleColor="text-sky-400" icon={<Terminal className="h-3.5 w-3.5" />}>
                                  <DetailField label="Log Source Ingestor" value={incident.ingestion?.source || "Standard Collector"} />
                                  {incident.ingestion?.integrity_hash && (
                                    <p className="font-mono text-[9px] text-slate-600 -mt-1 truncate">Hash: {incident.ingestion.integrity_hash}</p>
                                  )}
                                  <DetailLabel>Engineered Features (L1)</DetailLabel>
                                  <div className="grid grid-cols-2 gap-1.5 font-mono text-[10px]">
                                    <MiniStat label="Off-Hours" value={incident.feature_engineering?.temporal_features?.is_off_hours ? "Yes" : "No"} warn={incident.feature_engineering?.temporal_features?.is_off_hours} />
                                    <MiniStat label="Deviation" value={(incident.feature_engineering?.behavioral_features?.deviation_score || 0.85).toFixed(2)} />
                                    <div className="col-span-2 rounded-md bg-slate-900/80 px-2 py-1.5 border border-slate-800/60">
                                      <span className="block text-slate-600">Traffic Direction</span>
                                      <span className="font-bold uppercase text-slate-300">{incident.feature_engineering?.network_traffic_features?.traffic_direction || "North-South"}</span>
                                    </div>
                                  </div>
                                  <DetailField label="Anomaly Model (L2)" value={incident.anomaly_detection?.model || "AutoEncoder-ML"} />
                                  <div className="flex items-center justify-between -mt-1">
                                    <span className="text-[10px] text-slate-500">Score</span>
                                    <span className="rounded border border-red-500/20 bg-red-500/10 px-1.5 py-0.5 text-[9px] font-bold text-red-400">
                                      {(incident.anomaly_detection?.anomaly_score || 0.92).toFixed(2)}
                                    </span>
                                  </div>
                                  {incident.anomaly_detection?.baseline_deviation && (
                                    <p className="text-[10px] text-red-400/80">⚠ Baseline deviation: {incident.anomaly_detection.baseline_deviation}</p>
                                  )}
                                </DetailPanel>

                                {/* L3 + L4 */}
                                <DetailPanel title="Threats & Alignment" titleColor="text-pink-400" icon={<Brain className="h-3.5 w-3.5" />}>
                                  <DetailLabel>MITRE TTP Objectives (L2)</DetailLabel>
                                  <div className="flex flex-wrap gap-1">
                                    {(incident.threat_analysis?.mitre_tactics || ["Execution"]).map((t: string) => (
                                      <span key={t} className="rounded border border-slate-700/60 bg-slate-900/80 px-1.5 py-0.5 text-[9px] font-bold text-slate-300">{t}</span>
                                    ))}
                                  </div>
                                  <DetailLabel>CIS Security Framework (L3)</DetailLabel>
                                  <div className="flex items-center gap-2">
                                    <div className="flex h-6 w-6 items-center justify-center rounded border border-amber-500/20 bg-amber-500/10 text-[9px] font-black text-amber-400">CIS</div>
                                    <div>
                                      <p className="text-[11px] font-semibold text-slate-300">{incident.cis?.title || "Account Management & Control"}</p>
                                      <p className="text-[9px] text-slate-600">ID: {incident.cis?.benchmark_id || incident.cis?.controls_impacted?.[0] || "CIS-5"}</p>
                                    </div>
                                  </div>
                                  <DetailLabel>AI Intent Matrix (L4)</DetailLabel>
                                  <p className="text-[11px] font-semibold text-slate-300">{incident.ai_analysis?.intent || "Malicious Intrusion Attempt"}</p>
                                  <div className="grid grid-cols-3 gap-1 text-[9px] text-center font-mono uppercase">
                                    {[
                                      { k: "Conf.", v: incident.ai_analysis?.impact?.confidentiality?.split(" ")[0] || "HIGH", c: "text-red-400" },
                                      { k: "Integ.", v: incident.ai_analysis?.impact?.integrity?.split(" ")[0] || "HIGH", c: "text-red-400" },
                                      { k: "Avail.", v: incident.ai_analysis?.impact?.availability?.split(" ")[0] || "MED", c: "text-yellow-400" },
                                    ].map(({ k, v, c }) => (
                                      <div key={k} className="rounded-md bg-slate-900/80 border border-slate-800/60 py-1.5">
                                        <span className="block text-slate-600">{k}</span>
                                        <span className={`font-black ${c}`}>{v}</span>
                                      </div>
                                    ))}
                                  </div>
                                </DetailPanel>

                                {/* L5 + L6 */}
                                <DetailPanel title="CVSS & Response" titleColor="text-emerald-400" icon={<ShieldCheck className="h-3.5 w-3.5" />}>
                                  <DetailLabel>CVSS Base Vector</DetailLabel>
                                  <p className="rounded-md border border-slate-800/60 bg-slate-900/80 px-2 py-1.5 font-mono text-[9px] text-slate-400 break-all select-all">
                                    {incident.cvss?.vector_string || "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}
                                  </p>
                                  <DetailLabel>Recommended Containment (L6)</DetailLabel>
                                  <ul className="space-y-1">
                                    {(incident.response?.containment_steps || incident.ai_analysis?.next_steps?.slice(0, 2) || ["Network isolate asset immediately"]).map((s: string, i: number) => (
                                      <li key={i} className="flex items-start gap-1.5 text-[11px] text-slate-300">
                                        <span className="mt-0.5 text-red-500">•</span> {s}
                                      </li>
                                    ))}
                                  </ul>
                                  <DetailLabel>Next Playbook Actions</DetailLabel>
                                  <ul className="space-y-1">
                                    {(incident.response?.recommended_actions || ["Notify corporate security operations", "Rotate user credentials"]).slice(0, 2).map((a: string, i: number) => (
                                      <li key={i} className="flex items-start gap-1.5 text-[11px] text-slate-400 line-clamp-1">
                                        <span className="mt-0.5 text-sky-500">•</span> {a}
                                      </li>
                                    ))}
                                  </ul>
                                </DetailPanel>
                              </div>

                              {/* AI Narrative */}
                              <div className="rounded-xl border border-slate-800/60 bg-slate-950/60 p-4">
                                <p className="mb-2 flex items-center gap-1.5 text-[10px] font-extrabold uppercase tracking-widest text-sky-400">
                                  <Sparkles className="h-3.5 w-3.5 fill-current" /> AI Security Narrative & Incident Reconstruction
                                </p>
                                <p className="text-xs leading-relaxed text-slate-400 text-justify">
                                  {incident.ai_analysis?.narrative || incident.summary}
                                </p>
                              </div>

                              {/* Sparkline + Actions */}
                              <div className="flex flex-col items-center gap-4 sm:flex-row">
                                <div className="w-full sm:flex-1">
                                  <TemporalSparkline pipeline={incident} />
                                </div>
                                <div className="flex shrink-0 gap-2">
                                  <button
                                    onClick={(e) => handleToggleStatus(e, id, incidentStatus)}
                                    className={`inline-flex items-center gap-1.5 rounded-lg border px-4 py-2 text-xs font-bold transition ${
                                      isClosed
                                        ? "border-emerald-700/50 bg-emerald-950/30 text-emerald-300 hover:bg-emerald-900/40"
                                        : "border-slate-700/60 bg-slate-800 text-slate-300 hover:border-emerald-700/60 hover:text-emerald-400"
                                    }`}
                                  >
                                    {isClosed ? <><LockOpen className="h-3.5 w-3.5" /> Reopen Log</> : <><Lock className="h-3.5 w-3.5" /> Mark Reviewed & Close</>}
                                  </button>
                                  <Link href={`/incident/${id}`}>
                                    <button id={`btn-workspace-${id}`} className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700/60 bg-slate-800 px-4 py-2 text-xs font-bold text-slate-200 transition hover:bg-slate-700">
                                      Open Incident Workspace
                                    </button>
                                  </Link>
                                </div>
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })}
              </div>
            </AnimatePresence>
          )}
        </section>

        {/* ── Right Sidebar ─────────────────────────────────────── */}
        <section className="space-y-5">
          {/* Active Threat Risk Meter */}
          <div className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-5 space-y-4">
            <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-slate-400">
              <Activity className="h-3.5 w-3.5 text-cyan-400" /> Active Threat Risk
            </h3>
            <div className="space-y-3">
              <RiskBar label="Critical" count={summary.critical} total={summary.total} color="bg-red-500" />
              <RiskBar label="High"     count={summary.high}     total={summary.total} color="bg-orange-500" />
              <RiskBar label="Medium"   count={summary.total - summary.critical - summary.high} total={summary.total} color="bg-yellow-500" />
            </div>
            <div className="border-t border-slate-800/60 pt-3 text-center font-mono text-[10px] text-slate-600">
              {summary.critical > 0 ? "🟥 EXTREME — ACTION REQUIRED" : "🟨 PENDING ANALYST REVIEW"}
            </div>
          </div>

          {/* Event Frequency Chart */}
          <div>
            <EventFrequencyBars metrics={frequencyMetrics} />
          </div>
        </section>

      </div>
    </motion.div>
  );
}

/* ─── sub-components ─────────────────────────────────────────────── */

function StatCard({ label, value, sub, icon, color }: { label: string; value: number; sub: string; icon: React.ReactNode; color: "slate" | "red" | "orange" | "cyan" }) {
  const colorMap = {
    slate:  { bg: "bg-slate-900/60", border: "border-slate-800/60", icon: "text-slate-400", num: "text-slate-100" },
    red:    { bg: "bg-red-950/10",   border: "border-red-900/30",   icon: "text-red-400",   num: "text-red-300" },
    orange: { bg: "bg-orange-950/10",border: "border-orange-900/30",icon: "text-orange-400",num: "text-orange-300" },
    cyan:   { bg: "bg-cyan-950/10",  border: "border-cyan-900/30",  icon: "text-cyan-400",  num: "text-cyan-300" },
  };
  const c = colorMap[color];
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className={`flex items-start justify-between gap-3 rounded-xl border ${c.border} ${c.bg} p-4`}
    >
      <div>
        <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{label}</p>
        <p className={`mt-1.5 font-mono text-3xl font-black leading-none ${c.num}`}>{value}</p>
        <p className="mt-1 text-[10px] text-slate-600">{sub}</p>
      </div>
      <div className={`rounded-lg border ${c.border} bg-slate-950/60 p-2 ${c.icon}`}>{icon}</div>
    </motion.div>
  );
}

function FilterPillGroup({ options, active, onChange }: { options: string[]; active: string; onChange: (v: string) => void }) {
  return (
    <div className="flex rounded-lg border border-slate-800/60 bg-slate-950/60 p-0.5">
      {options.map((o) => (
        <button
          key={o}
          onClick={() => onChange(o)}
          className={`rounded-md px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider transition ${
            active === o ? "bg-slate-700 text-slate-100 shadow-sm" : "text-slate-600 hover:text-slate-300"
          }`}
        >
          {o}
        </button>
      ))}
    </div>
  );
}

function DetailPanel({ title, titleColor, icon, children }: { title: string; titleColor: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-slate-800/60 bg-slate-950/50 p-4 space-y-3">
      <h4 className={`flex items-center gap-1.5 border-b border-slate-800/60 pb-2 text-xs font-bold uppercase tracking-wider ${titleColor}`}>
        {icon} {title}
      </h4>
      <div className="space-y-2.5 text-xs">{children}</div>
    </div>
  );
}

function DetailLabel({ children }: { children: React.ReactNode }) {
  return <p className="text-[9px] font-extrabold uppercase tracking-widest text-slate-600 pt-1">{children}</p>;
}

function DetailField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <DetailLabel>{label}</DetailLabel>
      <p className="text-[11px] font-semibold text-slate-300">{value}</p>
    </div>
  );
}

function MiniStat({ label, value, warn }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="rounded-md border border-slate-800/60 bg-slate-900/80 px-2 py-1.5">
      <span className="block text-slate-600">{label}</span>
      <span className={`font-bold ${warn ? "text-orange-400" : "text-slate-300"}`}>{value}</span>
    </div>
  );
}

function RiskBar({ label, count, total, color }: { label: string; count: number; total: number; color: string }) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[11px] font-semibold text-slate-400">
        <span>{label}</span>
        <span className="font-mono text-slate-500">{count} <span className="text-slate-700">({Math.round(pct)}%)</span></span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800/80">
        <motion.div
          className={`h-full rounded-full ${color}`}
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.6, ease: "easeOut" }}
        />
      </div>
    </div>
  );
}

function PipelineDot({ label, status, color }: { label: string; status: "idle" | "done"; color: string }) {
  return (
    <div
      title={`${label}: ${status}`}
      className="group relative h-2 w-2 cursor-help rounded-full border border-slate-950 shrink-0"
      style={{
        backgroundColor: status === "done" ? color : "#1e293b",
        boxShadow: status === "done" ? `0 0 5px ${color}` : "none",
      }}
    >
      <span className="pointer-events-none absolute bottom-4 left-1/2 z-50 -translate-x-1/2 whitespace-nowrap rounded border border-slate-800 bg-slate-950 px-1.5 py-0.5 text-[8px] font-bold uppercase tracking-wider text-slate-300 opacity-0 transition group-hover:opacity-100">
        {label}: {status}
      </span>
    </div>
  );
}
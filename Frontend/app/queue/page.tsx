"use client";

import { useEffect, useMemo, useState, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ArrowRight,
  ChevronRight,
  Download,
  Filter,
  GitBranch,
  Search,
  ServerCrash,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Timer,
  SlidersHorizontal,
} from "lucide-react";
import {
  BarChart,
  Bar,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from "recharts";

import {
  EmptyState,
  Section,
  SeverityChip,
  VerdictChip,
} from "@/components/soc/primitives";
import {
  type Severity,
  formatTimestamp,
  normalizeSeverity,
  severityTone,
} from "@/lib/severity";
import { AnimatedList } from "@/components/ui/animated-list";

/* ─── Shapes we read from the API ──────────────────────────────────────────── */

type Incident = {
  event_id: string;
  raw_event?: Record<string, unknown>;
  dashboard?: Record<string, unknown>;
  detection?: Record<string, unknown>;
  cvss?: Record<string, unknown>;
  cis?: Record<string, unknown>;
  response?: Record<string, unknown>;
  mitre_attack?: { primary?: { technique_id?: string }; kill_chain_stage?: string };
  campaign?: {
    campaign_id: string;
    name: string;
    severity: string;
    incident_count: number;
    furthest_stage: string;
    progression_pct: number;
  } | null;
};

function QueueContent() {
  const searchParams = useSearchParams();
  const initialSeverity = searchParams.get("severity") as Severity | null;

  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [offline, setOffline] = useState(false);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"all" | Severity>(
    initialSeverity && ["critical", "high", "medium", "low", "benign"].includes(initialSeverity)
      ? initialSeverity
      : "all"
  );
  const [showFiltered, setShowFiltered] = useState(false);

  useEffect(() => {
    const sev = searchParams.get("severity") as Severity | null;
    if (sev && ["critical", "high", "medium", "low", "benign"].includes(sev)) {
      setSeverityFilter(sev);
    }
  }, [searchParams]);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const res = await fetch("/api/incidents", { cache: "no-store" });
        if (!res.ok) {
          if (alive) setOffline(true);
          return;
        }
        const data = await res.json();
        if (alive) setIncidents(data);
      } catch {
        if (alive) setOffline(true);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  /* Working queue. Benign and analyst-suppressed alerts stay out unless asked
     for — they are counted in the metrics, but they are not work. */
  const queue = useMemo(() => {
    if (!incidents) return [];
    const q = query.trim().toLowerCase();

    return incidents
      .filter((inc) => {
        const verdict = String((inc.detection as Record<string, string>)?.label ?? "").toLowerCase();
        if (!showFiltered && (verdict === "benign" || verdict === "suppressed")) return false;

        const severity = normalizeSeverity((inc.detection as Record<string, string>)?.severity);
        if (severityFilter !== "all" && severity !== severityFilter) return false;

        if (!q) return true;
        const dash = (inc.dashboard ?? {}) as Record<string, string>;
        const det = (inc.detection ?? {}) as Record<string, string>;
        return [
          dash.alert_title,
          dash.source_ip,
          dash.affected_host,
          dash.affected_user,
          det.threat_type,
          inc.mitre_attack?.primary?.technique_id,
          inc.campaign?.campaign_id,
          inc.event_id,
        ]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(q));
      })
      .sort((a, b) => {
        const sev = (i: Incident) =>
          severityTone((i.detection as Record<string, string>)?.severity).rank;
        const camp = (i: Incident) => (i.campaign ? 1 : 0);
        const stage = (i: Incident) => Number(i.mitre_attack?.kill_chain_stage ? 1 : 0);
        return (
          sev(b) - sev(a) ||
          camp(b) - camp(a) ||
          stage(b) - stage(a) ||
          Number((b.cvss as Record<string, number>)?.base_score ?? 0) -
            Number((a.cvss as Record<string, number>)?.base_score ?? 0)
        );
      });
  }, [incidents, query, severityFilter, showFiltered]);

  // Calculate attack type distribution from current incidents for the right side chart
  const attackTypeCounts = useMemo(() => {
    if (!incidents) return [];
    const counts: Record<string, number> = {};
    incidents.forEach((inc) => {
      const type =
        (inc.detection as Record<string, string>)?.threat_type ||
        inc.mitre_attack?.kill_chain_stage ||
        "Malware";
      // Normalize short names
      const shortName = type
        .replace(/_/g, " ")
        .split(" ")
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
        .join(" ");
      counts[shortName] = (counts[shortName] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [incidents]);

  if (offline) {
    return (
      <div className="mx-auto max-w-3xl pt-10">
        <EmptyState
          icon={<ServerCrash className="h-9 w-9" />}
          title="Backend not reachable"
          detail="Start it with `uvicorn api_server:app --port 8000`. Nothing on this page fabricates incidents when the API is down."
        />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-[1560px] space-y-4">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="eyebrow">Threat Monitoring</p>
          <h1 className="text-2xl font-semibold tracking-tight text-ink">
            Active Threat Detection
          </h1>
          <p className="text-xs text-muted">
            Real-time threat triage and priority event analysis
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowFiltered((v) => !v)}
            className="flex items-center gap-1.5 rounded-lg border border-rule bg-surface px-3 py-1.5 text-xs font-medium text-muted hover:text-ink hover:bg-raised transition-colors"
          >
            <SlidersHorizontal className="h-3.5 w-3.5 text-accent" />
            {showFiltered ? "Showing all" : "Noise hidden"}
          </button>
        </div>
      </div>

      {/* Main Grid: Left = Active Threats Table (8/12 cols), Right = Attack Types Chart (4/12 cols) */}
      <div className="grid gap-4 lg:grid-cols-12 items-start">
        {/* Left Column: Active Threats Table */}
        <div className="lg:col-span-8 rounded-xl border border-rule bg-[#0b0e0c] p-4 flex flex-col gap-3 shadow-lg">
          {/* Card Header with Filter Pills & Search */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule-soft/60 pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-accent" />
              <h2 className="font-semibold text-sm text-ink">Active Threats</h2>
              <span className="rounded-full bg-raised border border-rule px-2 py-0.5 text-[10px] text-faint">
                {queue.length} items
              </span>
            </div>

            {/* Severity Filter Pills */}
            <div className="flex items-center gap-1 bg-[#101612] p-1 rounded-lg border border-rule-soft">
              {(["all", "critical", "high", "medium", "low"] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setSeverityFilter(s)}
                  className={[
                    "rounded-md px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider transition-all",
                    severityFilter === s
                      ? s === "critical"
                        ? "bg-sev-critical/20 text-sev-critical border border-sev-critical/40 shadow-sm"
                        : s === "high"
                          ? "bg-sev-high/20 text-sev-high border border-sev-high/40 shadow-sm"
                          : s === "medium"
                            ? "bg-sev-medium/20 text-sev-medium border border-sev-medium/40 shadow-sm"
                            : s === "low"
                              ? "bg-sev-low/20 text-sev-low border border-sev-low/40 shadow-sm"
                              : "bg-accent/20 text-accent border border-accent/40 shadow-sm"
                      : "text-faint hover:text-muted bg-transparent border border-transparent",
                  ].join(" ")}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          {/* Search bar inside */}
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search threat name, IP, host, CVE, technique ID…"
              className="w-full rounded-lg border border-rule-soft bg-[#0e1310] py-2 pl-9 pr-3 text-xs text-ink placeholder-faint outline-none transition focus:border-accent-deep"
            />
          </div>

          {/* Table Header Row */}
          <div className="grid grid-cols-12 gap-2 px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-faint border-b border-rule-soft/50">
            <div className="col-span-5">Threat / Activity & Target</div>
            <div className="col-span-3 text-center">Severity</div>
            <div className="col-span-2 text-center">Verdict</div>
            <div className="col-span-1 text-center">CVSS</div>
            <div className="col-span-1 text-right">Action</div>
          </div>

          {/* Incidents List grouped by Severity with single encompassing watermark */}
          {!incidents ? (
            <div className="space-y-2 p-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="h-16 animate-pulse rounded-lg bg-raised/50" />
              ))}
            </div>
          ) : queue.length === 0 ? (
            <div className="p-8">
              <EmptyState
                icon={<ShieldCheck className="h-9 w-9" />}
                title={incidents.length === 0 ? "No incidents detected" : "No matching threats"}
                detail={
                  incidents.length === 0
                    ? "Replay an attack scenario from Simulation to stream new telemetry."
                    : "Clear your search or switch severity filters."
                }
              />
            </div>
          ) : (
            <div className="space-y-4 max-h-[620px] overflow-y-auto pr-1">
              {(["critical", "high", "medium", "low"] as Severity[]).map((sevTier) => {
                const groupItems = queue.filter(
                  (inc) => normalizeSeverity(inc.detection?.severity) === sevTier
                );
                if (groupItems.length === 0) return null;

                const watermarkBg =
                  sevTier === "critical"
                    ? "border-sev-critical/50 bg-gradient-to-b from-[#240a0a]/60 to-[#0e0404]/80 shadow-[0_0_30px_rgba(239,68,68,0.12)]"
                    : sevTier === "high"
                      ? "border-sev-high/50 bg-gradient-to-b from-[#221207]/60 to-[#0f0703]/80 shadow-[0_0_30px_rgba(249,115,22,0.12)]"
                      : sevTier === "medium"
                        ? "border-sev-medium/45 bg-gradient-to-b from-[#201907]/60 to-[#0e0a03]/80 shadow-[0_0_30px_rgba(250,178,25,0.09)]"
                        : "border-sev-low/40 bg-gradient-to-b from-[#0a1820]/60 to-[#040c10]/80 shadow-[0_0_30px_rgba(59,158,255,0.09)]";

                const watermarkText =
                  sevTier === "critical"
                    ? "text-sev-critical/[0.22]"
                    : sevTier === "high"
                      ? "text-sev-high/[0.22]"
                      : sevTier === "medium"
                        ? "text-sev-medium/[0.20]"
                        : "text-sev-low/[0.20]";

                return (
                  <div
                    key={sevTier}
                    className={`relative overflow-hidden rounded-xl border p-2.5 transition-all ${watermarkBg}`}
                  >
                    {/* One Single Giant Watermark Logo Encompassing all items in this severity category centered */}
                    <div
                      className={`pointer-events-none absolute inset-0 flex items-center justify-center select-none text-[80px] sm:text-[110px] font-black uppercase tracking-[0.2em] ${watermarkText}`}
                      aria-hidden
                    >
                      {sevTier}
                    </div>

                    {/* Stacked incident rows within this group using AnimatedList */}
                    <div className="relative z-10">
                      <AnimatedList
                        items={groupItems}
                        renderItem={(inc) => <ThreatrixQueueRow incident={inc} />}
                        displayScrollbar={false}
                        className="w-full"
                        itemClassName="mb-1.5 last:mb-0"
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Attack Types Distribution Chart */}
        <div className="lg:col-span-4 rounded-xl border border-rule bg-[#0b0e0c] p-4 flex flex-col gap-3 shadow-lg">
          <div className="flex items-center justify-between border-b border-rule-soft/60 pb-3">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-accent" />
              <h2 className="font-semibold text-sm text-ink">Attack Types</h2>
            </div>
            <span className="text-[10px] text-faint">Threat Distribution</span>
          </div>

          <div className="h-[280px] w-full pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={attackTypeCounts}
                margin={{ top: 10, right: 10, left: -20, bottom: 25 }}
              >
                <XAxis
                  dataKey="name"
                  tick={{ fill: "#5e7260", fontSize: 9 }}
                  interval={0}
                  angle={-25}
                  textAnchor="end"
                  axisLine={{ stroke: "#1a261a" }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: "#5e7260", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip
                  cursor={{ fill: "rgba(255, 255, 255, 0.04)" }}
                  contentStyle={{
                    backgroundColor: "#0a0e0a",
                    border: "1px solid #1a261a",
                    borderRadius: "6px",
                    fontSize: "11px",
                    color: "#f0fdf4",
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {attackTypeCounts.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={
                        index === 0
                          ? "#00f0ff"
                          : index === 1
                            ? "#00d2df"
                            : index === 2
                              ? "#00b2bf"
                              : "#008a94"
                      }
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Quick Summary list */}
          <div className="space-y-2 border-t border-rule-soft/50 pt-3">
            <p className="eyebrow">Top Attack Categories</p>
            {attackTypeCounts.slice(0, 4).map((item) => (
              <div
                key={item.name}
                className="flex items-center justify-between text-xs py-1 px-2 rounded bg-[#0e1310] border border-rule-soft/30"
              >
                <span className="text-muted truncate">{item.name}</span>
                <span className="font-semibold text-accent tabular">{item.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function QueuePage() {
  return (
    <Suspense fallback={<div className="mx-auto max-w-[1500px] h-96 animate-pulse rounded-lg bg-surface" />}>
      <QueueContent />
    </Suspense>
  );
}

function ThreatrixQueueRow({ incident }: { incident: Incident }) {
  const det = (incident.detection ?? {}) as Record<string, string | number>;
  const dash = (incident.dashboard ?? {}) as Record<string, string>;
  const cvss = (incident.cvss ?? {}) as Record<string, number | string>;
  const raw = (incident.raw_event ?? {}) as Record<string, string>;
  const severity = normalizeSeverity(det.severity);

  return (
    <div className="group relative rounded-lg border border-white/[0.06] bg-black/25 backdrop-blur-[2px] transition-all hover:border-white/20 hover:bg-white/[0.04]">
      <Link
        href={`/incident/${incident.event_id}`}
        className="relative z-10 grid grid-cols-12 items-center gap-2 px-3 py-2.5 text-xs"
      >
        {/* Threat title & context (No ID column) */}
        <div className="col-span-5 min-w-0 pr-2">
          <p className="font-semibold text-ink truncate group-hover:text-accent transition-colors">
            {dash.alert_title ?? String(det.threat_type ?? "Unclassified activity")}
          </p>
          <div className="flex items-center gap-2 text-[10px] text-faint truncate mt-0.5">
            <span className="truncate">
              {dash.source_ip ?? "Network"} → {dash.affected_host ?? "Host"}
            </span>
            <span>·</span>
            <span className="text-[9px] text-faint">{formatTimestamp(raw.timestamp)}</span>
            {incident.campaign ? (
              <span className="inline-flex items-center gap-0.5 rounded border border-sev-critical/35 bg-sev-critical/12 px-1 text-[8.5px] font-bold uppercase text-sev-critical shrink-0">
                <GitBranch className="h-2 w-2" />
                {incident.campaign.campaign_id}
              </span>
            ) : null}
          </div>
        </div>

        {/* Severity */}
        <div className="col-span-3 flex justify-center">
          <SeverityChip value={severity} size="xs" />
        </div>

        {/* Verdict */}
        <div className="col-span-2 flex justify-center">
          <VerdictChip value={det.label} />
        </div>

        {/* CVSS Score */}
        <div className="col-span-1 text-center">
          <span
            className={`font-mono font-bold tabular ${
              Number(cvss.base_score ?? 0) >= 8.5
                ? "text-sev-critical"
                : Number(cvss.base_score ?? 0) >= 7.0
                  ? "text-sev-high"
                  : "text-ink"
            }`}
          >
            {cvss.base_score ?? "—"}
          </span>
        </div>

        {/* Action button */}
        <div className="col-span-1 flex justify-end">
          <span className="inline-flex h-7 w-7 items-center justify-center rounded-full bg-surface border border-rule text-faint group-hover:text-ink group-hover:border-accent-deep group-hover:bg-raised transition-all">
            <ArrowRight className="h-3.5 w-3.5 transition group-hover:translate-x-0.5" />
          </span>
        </div>
      </Link>
    </div>
  );
}

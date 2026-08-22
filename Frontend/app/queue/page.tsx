"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  ArrowRight,
  GitBranch,
  Search,
  ServerCrash,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { EmptyState, SeverityChip, VerdictChip } from "@/components/soc/primitives";
import { AnimatedList } from "@/components/ui/animated-list";
import { seriesColor, useChartTheme } from "@/lib/chart-theme";
import { type Severity, formatTimestamp, normalizeSeverity, severityTone } from "@/lib/severity";

/**
 * Triage queue.
 *
 * The work list, worst first. The dashboard answers "what is the state of
 * things"; this answers "what do I open next", which is a different question and
 * wants a different shape — one row per alert, dense, sortable by the things
 * that decide priority.
 */

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

const SEVERITY_TIERS = ["critical", "high", "medium", "low"] as const;
const FILTERS = ["all", "critical", "high", "medium", "low"] as const;

function isSeverity(value: string | null): value is Severity {
  return value !== null && ["critical", "high", "medium", "low", "benign"].includes(value);
}

function QueueContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const chart = useChartTheme();

  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [offline, setOffline] = useState(false);
  const [query, setQuery] = useState("");
  const [showFiltered, setShowFiltered] = useState(false);

  /**
   * The severity filter lives in the URL, not in component state.
   *
   * The dashboard links straight here with ?severity=critical, so the URL has to
   * be honoured anyway. Holding it in state as well means two sources of truth
   * and an effect to copy one into the other, which is both a re-render and a
   * bug waiting for the two to disagree. Reading it directly also makes a
   * filtered queue a link someone can send.
   */
  const severityParam = searchParams.get("severity");
  const severityFilter: "all" | Severity = isSeverity(severityParam) ? severityParam : "all";

  const setSeverityFilter = (next: "all" | Severity) => {
    const params = new URLSearchParams(searchParams.toString());
    if (next === "all") params.delete("severity");
    else params.set("severity", next);
    const qs = params.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  };

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
        const det = (inc.detection ?? {}) as Record<string, string>;
        const verdict = String(det.label ?? "").toLowerCase();
        if (!showFiltered && (verdict === "benign" || verdict === "suppressed")) return false;

        if (severityFilter !== "all" && normalizeSeverity(det.severity) !== severityFilter) {
          return false;
        }

        if (!q) return true;
        const dash = (inc.dashboard ?? {}) as Record<string, string>;
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
        const stage = (i: Incident) => (i.mitre_attack?.kill_chain_stage ? 1 : 0);
        return (
          sev(b) - sev(a) ||
          camp(b) - camp(a) ||
          stage(b) - stage(a) ||
          Number((b.cvss as Record<string, number>)?.base_score ?? 0) -
            Number((a.cvss as Record<string, number>)?.base_score ?? 0)
        );
      });
  }, [incidents, query, severityFilter, showFiltered]);

  /**
   * Distribution of what is in the queue.
   *
   * Counted over the same working set the table shows, not over every stored
   * incident. Sitting side by side, a chart that ignores the active filter and a
   * list that honours it disagree on screen, and the reader has no way to tell
   * which one answered their question.
   */
  const attackTypes = useMemo(() => {
    const counts = new Map<string, number>();
    for (const inc of queue) {
      const det = (inc.detection ?? {}) as Record<string, string>;
      const raw = det.threat_type || inc.mitre_attack?.kill_chain_stage || "Unclassified";
      const name = raw
        .replace(/_/g, " ")
        .split(" ")
        .filter(Boolean)
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
        .join(" ");
      counts.set(name, (counts.get(name) ?? 0) + 1);
    }
    return [...counts.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [queue]);

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
    <div className="screen mx-auto max-w-[1560px] space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Triage</p>
          <h1 className="text-2xl font-semibold tracking-tight text-ink">Active threats</h1>
          <p className="text-xs text-muted">Worst first. Open the top row and work down.</p>
        </div>

        <button
          onClick={() => setShowFiltered((v) => !v)}
          aria-pressed={showFiltered}
          className="flex items-center gap-1.5 rounded-lg border border-rule bg-surface px-3 py-1.5 text-xs font-medium text-muted transition-colors hover:bg-raised hover:text-ink"
        >
          <SlidersHorizontal className="h-3.5 w-3.5 text-accent" />
          {showFiltered ? "Showing benign too" : "Benign hidden"}
        </button>
      </div>

      <div className="grid items-start gap-4 lg:grid-cols-12">
        {/* ── The queue ── */}
        <div className="flex flex-col gap-3 rounded-xl border border-rule bg-surface p-4 lg:col-span-8">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule-soft/60 pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-accent" />
              <h2 className="text-sm font-semibold text-ink">Queue</h2>
              <span className="rounded-full border border-rule bg-raised px-2 py-0.5 text-[10px] text-faint">
                {queue.length} {queue.length === 1 ? "item" : "items"}
              </span>
            </div>

            <div
              className="flex items-center gap-1 rounded-lg border border-rule-soft bg-sunk p-1"
              role="group"
              aria-label="Filter by severity"
            >
              {FILTERS.map((s) => {
                const active = severityFilter === s;
                const tone = s === "all" ? null : severityTone(s);
                return (
                  <button
                    key={s}
                    onClick={() => setSeverityFilter(s)}
                    aria-pressed={active}
                    className={[
                      "rounded-md border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider transition-all",
                      active
                        ? tone
                          ? tone.chip
                          : "border-accent/40 bg-accent/20 text-accent"
                        : "border-transparent bg-transparent text-faint hover:text-muted",
                    ].join(" ")}
                  >
                    {s}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="relative">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint"
              aria-hidden
            />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              aria-label="Search the queue"
              placeholder="Search threat, IP, host, user, technique ID…"
              className="w-full rounded-lg border border-rule-soft bg-sunk py-2 pl-9 pr-3 text-xs text-ink outline-none transition placeholder:text-faint focus:border-accent-deep"
            />
          </div>

          <div className="grid grid-cols-12 gap-2 border-b border-rule-soft/50 px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-faint">
            <div className="col-span-5">Threat and target</div>
            <div className="col-span-3 text-center">Severity</div>
            <div className="col-span-2 text-center">Verdict</div>
            <div className="col-span-1 text-center">CVSS</div>
            <div className="col-span-1 text-right">Open</div>
          </div>

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
                title={incidents.length === 0 ? "No incidents stored" : "Nothing matches"}
                detail={
                  incidents.length === 0
                    ? "Replay an attack scenario from Simulation to stream new telemetry."
                    : "Clear the search, or widen the severity filter."
                }
              />
            </div>
          ) : (
            <div className="space-y-4">
              {SEVERITY_TIERS.map((tier) => {
                const group = queue.filter(
                  (inc) =>
                    normalizeSeverity((inc.detection as Record<string, string>)?.severity) === tier,
                );
                if (group.length === 0) return null;
                const tone = severityTone(tier);

                return (
                  <div
                    key={tier}
                    className={`relative overflow-hidden rounded-xl border p-2.5 ${tone.border}`}
                  >
                    {/* The tier name, once, behind the whole group — so a long
                        queue still tells you which band you are looking at
                        without a sticky header. */}
                    <div
                      className={`pointer-events-none absolute inset-0 flex select-none items-center justify-center text-[80px] font-black uppercase tracking-[0.2em] opacity-[0.13] sm:text-[110px] ${tone.text}`}
                      aria-hidden
                    >
                      {tier}
                    </div>

                    <div className="relative z-10">
                      <AnimatedList
                        items={group}
                        renderItem={(inc) => <QueueRow incident={inc} />}
                        displayScrollbar={false}
                        showGradients={false}
                        enableArrowNavigation={false}
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

        {/* ── Distribution ── */}
        <div className="flex flex-col gap-3 rounded-xl border border-rule bg-surface p-4 lg:col-span-4">
          <div className="flex items-center justify-between border-b border-rule-soft/60 pb-3">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-accent" />
              <h2 className="text-sm font-semibold text-ink">Attack types</h2>
            </div>
            <span className="text-[10px] text-faint">In this queue</span>
          </div>

          {attackTypes.length === 0 ? (
            <p className="py-10 text-center text-xs text-faint">
              Nothing in the queue to break down.
            </p>
          ) : (
            <>
              <div className="h-[280px] w-full pt-2">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={attackTypes} margin={{ top: 10, right: 10, left: -20, bottom: 28 }}>
                    <XAxis
                      dataKey="name"
                      tick={{ fill: chart.axis, fontSize: 9 }}
                      interval={0}
                      angle={-25}
                      textAnchor="end"
                      axisLine={{ stroke: chart.grid }}
                      tickLine={false}
                    />
                    <YAxis
                      tick={{ fill: chart.axis, fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                      allowDecimals={false}
                    />
                    <Tooltip
                      cursor={{ fill: chart.cursor }}
                      contentStyle={{
                        backgroundColor: chart.tooltipBg,
                        border: `1px solid ${chart.tooltipBorder}`,
                        borderRadius: "6px",
                        fontSize: "11px",
                        color: chart.tooltipText,
                      }}
                    />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {attackTypes.map((entry, index) => (
                        <Cell key={entry.name} fill={seriesColor(chart, index)} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div className="space-y-2 border-t border-rule-soft/50 pt-3">
                <p className="eyebrow">Most common</p>
                {attackTypes.slice(0, 4).map((item, index) => (
                  <div
                    key={item.name}
                    className="flex items-center justify-between gap-2 rounded border border-rule-soft/30 bg-sunk px-2 py-1 text-xs"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <span
                        className="h-2 w-2 shrink-0 rounded-sm"
                        style={{ backgroundColor: seriesColor(chart, index) }}
                        aria-hidden
                      />
                      <span className="truncate text-muted">{item.name}</span>
                    </span>
                    <span className="tabular font-semibold text-accent">{item.count}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function QueueRow({ incident }: { incident: Incident }) {
  const det = (incident.detection ?? {}) as Record<string, string | number>;
  const dash = (incident.dashboard ?? {}) as Record<string, string>;
  const cvss = (incident.cvss ?? {}) as Record<string, number | string>;
  const raw = (incident.raw_event ?? {}) as Record<string, string>;
  const score = Number(cvss.base_score ?? 0);

  return (
    <div className="group relative rounded-lg border border-rule-soft/60 bg-ground/70 backdrop-blur-[2px] transition-all hover:border-accent-deep hover:bg-raised/70">
      <Link
        href={`/incident/${incident.event_id}`}
        className="relative z-10 grid grid-cols-12 items-center gap-2 px-3 py-2.5 text-xs"
      >
        <div className="col-span-5 min-w-0 pr-2">
          <p className="truncate font-semibold text-ink transition-colors group-hover:text-accent">
            {dash.alert_title ?? String(det.threat_type ?? "Unclassified activity")}
          </p>
          <div className="mt-0.5 flex items-center gap-2 truncate text-[10px] text-faint">
            <span className="truncate">
              {dash.source_ip ?? "Network"} → {dash.affected_host ?? "Host"}
            </span>
            <span aria-hidden>·</span>
            <span>{formatTimestamp(raw.timestamp)}</span>
            {incident.campaign ? (
              <span className="inline-flex shrink-0 items-center gap-0.5 rounded border border-sev-critical/35 bg-sev-critical/12 px-1 text-[8.5px] font-bold uppercase text-sev-critical">
                <GitBranch className="h-2 w-2" />
                {incident.campaign.campaign_id}
              </span>
            ) : null}
          </div>
        </div>

        <div className="col-span-3 flex justify-center">
          <SeverityChip value={det.severity} size="xs" />
        </div>

        <div className="col-span-2 flex justify-center">
          <VerdictChip value={det.label} />
        </div>

        <div className="col-span-1 text-center">
          <span
            className={`mono tabular font-bold ${
              score >= 9.0
                ? "text-sev-critical"
                : score >= 7.0
                  ? "text-sev-high"
                  : score > 0
                    ? "text-ink"
                    : "text-faint"
            }`}
          >
            {cvss.base_score ?? "—"}
          </span>
        </div>

        <div className="col-span-1 flex justify-end">
          <span
            className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-rule bg-surface text-faint transition-all group-hover:border-accent-deep group-hover:bg-raised group-hover:text-ink"
            aria-hidden
          >
            <ArrowRight className="h-3.5 w-3.5 transition group-hover:translate-x-0.5" />
          </span>
        </div>
      </Link>
    </div>
  );
}

export default function QueuePage() {
  return (
    <Suspense
      fallback={<div className="mx-auto h-96 max-w-[1560px] animate-pulse rounded-lg bg-surface" />}
    >
      <QueueContent />
    </Suspense>
  );
}

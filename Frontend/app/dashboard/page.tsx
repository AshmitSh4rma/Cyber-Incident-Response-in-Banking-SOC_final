"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { AnimatePresence, motion } from "framer-motion";
import { ArrowRight, GitBranch, Search, ServerCrash, ShieldCheck, Timer } from "lucide-react";

import {
  Block,
  ClockRow,
  EmptyState,
  HeroFigure,
  KillChainMeter,
  PlainEnglish,
  Screen,
  Section,
  SeverityBar,
  SeverityChip,
  Skeleton,
  StatTile,
  VerdictChip,
  type Clock,
} from "@/components/soc/primitives";
import { useDetail } from "@/lib/detail";
import { EASE_OUT, fadeIn, riseIn } from "@/lib/motion";
import { type Severity, formatTimestamp, normalizeSeverity, severityTone } from "@/lib/severity";

type Incident = {
  event_id: string;
  dashboard?: Record<string, string>;
  detection?: Record<string, unknown>;
  cvss?: Record<string, unknown>;
  cis?: Record<string, unknown>;
  response?: Record<string, unknown>;
  raw_event?: Record<string, unknown>;
  mitre_attack?: { primary?: { technique_id?: string }; kill_chain_stage?: string };
  campaign?: { campaign_id: string; furthest_stage: string; incident_count: number } | null;
};

type Metrics = {
  queue: { total_alerts: number; benign_filtered: number; analyst_suppressed: number; actionable: number; severity: Record<string, number> };
  consolidation: { investigations: number; campaigns: number; standalone: number; ratio: number };
  coverage: { cis_mapped_pct: number; attack_mapped_pct: number; cvss_scored_pct: number };
  time: { pipeline_seconds: number | null; hours_saved: number };
  response: { gated_actions: number; auto_share_pct: number };
};

type NotificationItem = {
  kind: "campaign" | "incident";
  id: string;
  title: string;
  severity: string;
  stage: string;
  alert_count: number;
  notification: { clocks: Clock[]; tightest: Clock };
};

type Campaign = {
  campaign_id: string;
  name: string;
  severity: string;
  incident_count: number;
  furthest_stage: string;
  furthest_stage_order: number;
  progression_pct: number;
  kill_chain: { order: number }[];
  assets: string[];
};

export default function DashboardPage() {
  const { isAnalyst } = useDetail();

  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [notifications, setNotifications] = useState<{ count: number; items: NotificationItem[]; disclaimer: string } | null>(null);
  const [campaigns, setCampaigns] = useState<Campaign[] | null>(null);
  const [offline, setOffline] = useState(false);

  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"all" | Severity>("all");

  useEffect(() => {
    let alive = true;
    const get = async <T,>(path: string): Promise<T | null> => {
      try {
        const res = await fetch(path, { cache: "no-store" });
        return res.ok ? ((await res.json()) as T) : null;
      } catch {
        return null;
      }
    };
    (async () => {
      const [inc, met, notif, camp] = await Promise.all([
        get<Incident[]>("/api/incidents"),
        get<Metrics>("/api/metrics"),
        get<{ count: number; items: NotificationItem[]; disclaimer: string }>("/api/notifications"),
        get<{ campaigns: Campaign[] }>("/api/campaigns"),
      ]);
      if (!alive) return;
      if (inc === null && met === null) {
        setOffline(true);
        return;
      }
      setIncidents(inc ?? []);
      setMetrics(met);
      setNotifications(notif);
      setCampaigns(camp?.campaigns ?? []);
    })();
    return () => {
      alive = false;
    };
  }, []);

  const queue = useMemo(() => {
    if (!incidents) return [];
    const q = query.trim().toLowerCase();
    return incidents
      .filter((inc) => {
        const det = (inc.detection ?? {}) as Record<string, string>;
        const verdict = String(det.label ?? "").toLowerCase();
        // Benign and dismissed alerts are counted in the metrics but are never
        // work, so they stay out of the queue entirely.
        if (verdict === "benign" || verdict === "suppressed") return false;
        if (severityFilter !== "all" && normalizeSeverity(det.severity) !== severityFilter) return false;
        if (!q) return true;
        const dash = inc.dashboard ?? {};
        return [dash.alert_title, dash.source_ip, dash.affected_host, dash.affected_user, det.threat_type, inc.campaign?.campaign_id]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(q));
      })
      .sort((a, b) => {
        const sev = (i: Incident) => severityTone((i.detection as Record<string, string>)?.severity).rank;
        const camp = (i: Incident) => (i.campaign ? 1 : 0);
        return sev(b) - sev(a) || camp(b) - camp(a);
      });
  }, [incidents, query, severityFilter]);

  if (offline) {
    return (
      <Screen className="max-w-3xl pt-8">
        <EmptyState
          icon={<ServerCrash className="h-9 w-9" />}
          title="Can't reach the analysis service"
          detail="Start it with `uvicorn api_server:app --port 8000`. This page never invents incidents when the service is down."
        />
      </Screen>
    );
  }

  const urgent = notifications?.items?.[0];
  const severityCounts = (metrics?.queue.severity ?? {}) as Partial<Record<Severity, number>>;

  return (
    <Screen>
      {/* ── The two things that matter on arrival ────────────────────────────── */}
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        <Block className="rounded-lg border border-rule bg-surface p-5">
          {metrics ? (
            <>
              <HeroFigure
                value={metrics.consolidation.investigations}
                unit={metrics.consolidation.investigations === 1 ? "thing to look at" : "things to look at"}
                label="Right now"
                detail={
                  <>
                    We read <span className="tabular font-semibold text-ink">{metrics.queue.total_alerts}</span>{" "}
                    security alerts. Most were normal activity or repeats of something already
                    dismissed. What is left is grouped into the {metrics.consolidation.investigations}{" "}
                    {metrics.consolidation.investigations === 1 ? "case" : "cases"} below.
                  </>
                }
              />
              <div className="mt-5 space-y-3 border-t border-rule-soft pt-4">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-faint">
                  How serious they are
                </p>
                <SeverityBar counts={severityCounts} total={metrics.queue.actionable} />
              </div>
            </>
          ) : (
            <Skeleton className="h-56" />
          )}
        </Block>

        {/* The clock. Most legible thing on the screen for a non-technical reader. */}
        <Section
          title="Time left to report"
          hint={urgent ? "Regulators must be told within hours" : "Nothing needs reporting"}
          actions={
            notifications?.count ? (
              <Link
                href="/compliance"
                className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-accent transition hover:gap-1.5"
              >
                All <ArrowRight className="h-3 w-3" />
              </Link>
            ) : null
          }
        >
          {!notifications ? (
            <Skeleton className="h-40" />
          ) : urgent ? (
            <div className="space-y-4">
              <Link
                href={urgent.kind === "campaign" ? `/campaigns/${urgent.id}` : `/incident/${urgent.id}`}
                className="group block rounded-md border border-rule bg-raised/50 p-3 transition hover:border-accent-deep hover:bg-raised"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityChip value={urgent.severity} size="xs" />
                  <span className="text-[10px] text-muted">
                    {urgent.alert_count} related alerts · got as far as {urgent.stage}
                  </span>
                </div>
                <p className="mt-1.5 flex items-center gap-1.5 text-[13px] font-medium text-ink">
                  <span className="truncate">{urgent.title}</span>
                  <ArrowRight className="h-3 w-3 shrink-0 text-faint transition group-hover:translate-x-0.5" />
                </p>
              </Link>

              <ClockRow clock={urgent.notification.tightest} prominent />

              <AnimatePresence initial={false}>
                {isAnalyst ? (
                  <motion.div variants={fadeIn} initial="hidden" animate="shown" exit="hidden" className="space-y-3">
                    {urgent.notification.clocks.slice(1).map((clock) => (
                      <ClockRow key={clock.regime_id} clock={clock} />
                    ))}
                    <p className="text-[10px] leading-relaxed text-faint">{notifications.disclaimer}</p>
                  </motion.div>
                ) : null}
              </AnimatePresence>

              {!isAnalyst ? (
                <PlainEnglish>
                  A bank has to tell its regulator about a serious incident within hours,
                  not days. This counts down from the moment we worked out what happened.
                </PlainEnglish>
              ) : null}
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-xs text-muted">
                <ShieldCheck className="h-4 w-4 text-sev-benign" />
                Nothing needs reporting to a regulator
              </div>
              <PlainEnglish>
                Attempts that were blocked, and scanning that never got in, are not
                reportable incidents.
              </PlainEnglish>
            </div>
          )}
        </Section>
      </div>

      {/* ── Cases ────────────────────────────────────────────────────────────── */}
      {campaigns && campaigns.length > 0 ? (
        <Section
          title="What happened"
          hint="Separate alerts that turned out to be the same attacker"
          actions={
            <Link
              href="/campaigns"
              className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-accent transition hover:gap-1.5"
            >
              Open <ArrowRight className="h-3 w-3" />
            </Link>
          }
        >
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {campaigns.map((c, i) => {
              const tone = severityTone(c.severity);
              return (
                <motion.div key={c.campaign_id} variants={riseIn} custom={i}>
                  <Link
                    href={`/campaigns/${c.campaign_id}`}
                    className={`group flex h-full flex-col gap-3 rounded-md border ${tone.border} bg-raised/40 p-3.5 transition hover:-translate-y-0.5 hover:bg-raised hover:shadow-lg`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <SeverityChip value={c.severity} size="xs" />
                      <span className="figure shrink-0 text-lg font-semibold leading-none text-ink">
                        {c.progression_pct}%
                      </span>
                    </div>
                    <p className="line-clamp-2 text-[13px] font-medium leading-snug text-ink">{c.name}</p>
                    <KillChainMeter
                      reachedOrders={c.kill_chain.map((s) => s.order)}
                      furthestOrder={c.furthest_stage_order}
                    />
                    <p className="mt-auto flex items-center justify-between text-[10px] text-muted">
                      <span>{c.incident_count} alerts</span>
                      <span className="font-medium text-ink">reached {c.furthest_stage}</span>
                    </p>
                  </Link>
                </motion.div>
              );
            })}
          </div>
        </Section>
      ) : null}

      {/* ── Supporting numbers — analysts only ──────────────────────────────── */}
      <AnimatePresence initial={false}>
        {isAnalyst && metrics ? (
          <motion.div
            variants={fadeIn}
            initial="hidden"
            animate="shown"
            exit="hidden"
            className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-rule bg-rule sm:grid-cols-3 lg:grid-cols-5"
          >
            <div className="bg-surface">
              <StatTile label="Alerts ingested" value={metrics.queue.total_alerts} sub={`${metrics.queue.actionable} needed a decision`} />
            </div>
            <div className="bg-surface">
              <StatTile label="Alerts per case" value={`${metrics.consolidation.ratio}:1`} animate={false} sub={`${metrics.consolidation.campaigns} chains, ${metrics.consolidation.standalone} standalone`} />
            </div>
            <div className="bg-surface">
              <StatTile label="Containment automated" value={`${metrics.response.auto_share_pct}%`} animate={false} sub={`${metrics.response.gated_actions} held for a human`} />
            </div>
            <div className="bg-surface">
              <StatTile label="Analyst hours saved" value={metrics.time.hours_saved} unit="hrs" animate={false} sub="Modelled — assumption in the API response" />
            </div>
            <div className="bg-surface">
              <StatTile
                label="Pipeline latency"
                value={metrics.time.pipeline_seconds != null ? `${metrics.time.pipeline_seconds}s` : "—"}
                animate={false}
                sub={`Control mapped ${metrics.coverage.cis_mapped_pct}% · ATT&CK ${metrics.coverage.attack_mapped_pct}%`}
              />
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>

      {/* ── Queue ────────────────────────────────────────────────────────────── */}
      <Section
        title="Things to look at"
        hint="Most serious first"
        flush
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <label className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3 w-3 -translate-y-1/2 text-faint" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search"
                aria-label="Search"
                className="w-40 rounded border border-rule bg-sunk py-1.5 pl-7 pr-2 text-[11px] text-ink placeholder-faint outline-none transition focus:w-52 focus:border-accent-deep"
              />
            </label>
            <div className="flex rounded border border-rule bg-sunk p-0.5">
              {(["all", "critical", "high", "medium"] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setSeverityFilter(s)}
                  className="relative px-2 py-1 text-[10px] font-semibold uppercase tracking-wider transition-colors"
                >
                  {severityFilter === s ? (
                    <motion.span layoutId="sev-pill" transition={{ duration: 0.22, ease: EASE_OUT }} className="absolute inset-0 rounded bg-raised" />
                  ) : null}
                  <span className={`relative ${severityFilter === s ? "text-ink" : "text-faint hover:text-muted"}`}>{s}</span>
                </button>
              ))}
            </div>
          </div>
        }
      >
        {!incidents ? (
          <div className="space-y-px p-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-14" />
            ))}
          </div>
        ) : queue.length === 0 ? (
          <div className="p-4">
            <EmptyState
              icon={<ShieldCheck className="h-9 w-9" />}
              title={incidents.length === 0 ? "Nothing here yet" : "Nothing matches"}
              detail={
                incidents.length === 0
                  ? "Run a scenario from Simulation to send activity through the system."
                  : "Clear the search or widen the filter."
              }
            />
          </div>
        ) : (
          <ul className="divide-y divide-rule-soft">
            <AnimatePresence initial={false}>
              {queue.map((inc) => (
                <QueueRow key={inc.event_id} incident={inc} analyst={isAnalyst} />
              ))}
            </AnimatePresence>
          </ul>
        )}
      </Section>
    </Screen>
  );
}

function QueueRow({ incident, analyst }: { incident: Incident; analyst: boolean }) {
  const det = (incident.detection ?? {}) as Record<string, string | number>;
  const dash = incident.dashboard ?? {};
  const cvss = (incident.cvss ?? {}) as Record<string, number | string>;
  const cis = (incident.cis ?? {}) as Record<string, string>;
  const resp = (incident.response ?? {}) as Record<string, unknown>;
  const raw = (incident.raw_event ?? {}) as Record<string, string>;
  const tone = severityTone(det.severity);

  return (
    <motion.li layout variants={fadeIn} initial="hidden" animate="shown" exit="hidden" className="group relative">
      <Link
        href={`/incident/${incident.event_id}`}
        className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3 transition hover:bg-raised/40"
      >
        <motion.span
          className={`absolute left-0 top-0 h-full w-0.5 ${tone.mark}`}
          initial={{ opacity: 0.5 }}
          whileHover={{ opacity: 1 }}
          aria-hidden
        />

        <div className="min-w-0 flex-1 basis-72 space-y-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <SeverityChip value={det.severity} size="xs" />
            {incident.campaign ? (
              <span className="inline-flex items-center gap-1 rounded border border-sev-critical/35 bg-sev-critical/12 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-sev-critical">
                <GitBranch className="h-2.5 w-2.5" />
                part of a chain
              </span>
            ) : null}
            {resp.requires_human_approval ? (
              <span className="inline-flex items-center gap-1 rounded border border-sev-high/35 bg-sev-high/12 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-sev-high">
                <Timer className="h-2.5 w-2.5" />
                needs you
              </span>
            ) : null}
            {analyst ? <VerdictChip value={det.label} /> : null}
          </div>

          <p className="truncate text-[13px] font-medium text-ink">
            {dash.alert_title ?? String(det.threat_type ?? "Unclassified activity")}
          </p>
          {/* The title already names the source and target, so this line carries
              what it does not: the account, and how far the attacker got. */}
          <p className="truncate text-[10px] text-muted">
            {[
              dash.affected_user && dash.affected_user !== "unattributed"
                ? `account ${dash.affected_user}`
                : null,
              incident.mitre_attack?.kill_chain_stage && incident.mitre_attack.kill_chain_stage !== "unmapped"
                ? `reached ${incident.mitre_attack.kill_chain_stage}`
                : null,
            ]
              .filter(Boolean)
              .join(" · ") || "no account involved"}
          </p>
        </div>

        {/* Identifiers only for analysts. In simple mode the row is a sentence. */}
        <div className="flex shrink-0 items-center gap-x-5 gap-y-1.5 text-[10px]">
          <AnimatePresence initial={false}>
            {analyst ? (
              <motion.span
                variants={fadeIn}
                initial="hidden"
                animate="shown"
                exit="hidden"
                className="flex items-center gap-x-4"
              >
                {incident.mitre_attack?.primary?.technique_id ? (
                  <span className="mono rounded border border-rule bg-raised px-1.5 py-0.5 text-accent">
                    {incident.mitre_attack.primary.technique_id}
                  </span>
                ) : null}
                {cis.benchmark_id ? <span className="mono text-faint">{cis.benchmark_id}</span> : null}
                <span className="flex items-baseline gap-1">
                  <span className="text-faint">CVSS</span>
                  <span className="tabular font-semibold text-ink">{cvss.base_score ?? "—"}</span>
                </span>
              </motion.span>
            ) : null}
          </AnimatePresence>
          <span className="w-28 shrink-0 whitespace-nowrap text-right text-faint">{formatTimestamp(raw.timestamp)}</span>
          <ArrowRight className="h-3 w-3 text-faint transition group-hover:translate-x-0.5 group-hover:text-muted" />
        </div>
      </Link>
    </motion.li>
  );
}

"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  Clock,
  GitBranch,
  Search,
  ServerCrash,
  ShieldCheck,
  Timer,
} from "lucide-react";

import {
  ClockRow,
  EmptyState,
  HeroFigure,
  KillChainMeter,
  PlainEnglish,
  Section,
  SeverityBar,
  SeverityChip,
  StatTile,
  VerdictChip,
  type Clock as ClockType,
} from "@/components/soc/primitives";
import {
  type Severity,
  formatTimestamp,
  normalizeSeverity,
  severityTone,
} from "@/lib/severity";

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

type Metrics = {
  queue: {
    total_alerts: number;
    benign_filtered: number;
    analyst_suppressed: number;
    actionable: number;
    severity: Record<string, number>;
  };
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
  notification: { clocks: ClockType[]; tightest: ClockType; reasons: string[] };
};

type Notifications = {
  count: number;
  overdue: number;
  items: NotificationItem[];
  disclaimer: string;
};

/* ─── Page ─────────────────────────────────────────────────────────────────── */

export default function DashboardPage() {
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [notifications, setNotifications] = useState<Notifications | null>(null);
  const [offline, setOffline] = useState(false);

  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"all" | Severity>("all");
  const [showFiltered, setShowFiltered] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      const get = async <T,>(path: string): Promise<T | null> => {
        try {
          const res = await fetch(path, { cache: "no-store" });
          if (!res.ok) return null;
          return (await res.json()) as T;
        } catch {
          return null;
        }
      };

      const [inc, met, notif] = await Promise.all([
        get<Incident[]>("/api/incidents"),
        get<Metrics>("/api/metrics"),
        get<Notifications>("/api/notifications"),
      ]);

      if (!alive) return;
      if (inc === null && met === null) {
        setOffline(true);
        return;
      }
      setIncidents(inc ?? []);
      setMetrics(met);
      setNotifications(notif);
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
        // What to look at first: campaign membership outranks a lone alert of the
        // same severity, because a correlated alert is part of something moving.
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

  const severityCounts = (metrics?.queue.severity ?? {}) as Partial<Record<Severity, number>>;
  const urgent = notifications?.items?.[0];

  return (
    <div className="mx-auto max-w-[1500px] space-y-5">
      {/* ── Lead: what the pipeline did, and the one thing that is on a clock ── */}
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
        <div className="rounded-md border border-rule bg-surface p-5">
          {metrics ? (
            <HeroFigure
              value={metrics.consolidation.investigations}
              unit={metrics.consolidation.investigations === 1 ? "investigation" : "investigations"}
              label="Your queue right now"
              detail={
                <>
                  From{" "}
                  <span className="tabular font-semibold text-ink">
                    {metrics.queue.total_alerts}
                  </span>{" "}
                  raw alerts.{" "}
                  <span className="tabular font-semibold text-ink">
                    {metrics.queue.benign_filtered + metrics.queue.analyst_suppressed}
                  </span>{" "}
                  were filtered as normal business traffic or already-dismissed patterns,
                  and{" "}
                  <span className="tabular font-semibold text-ink">
                    {metrics.consolidation.campaigns}
                  </span>{" "}
                  groups of alerts turned out to be the same intrusion.
                </>
              }
            />
          ) : (
            <div className="h-[104px] animate-pulse rounded bg-raised" />
          )}

          <div className="mt-5 space-y-3 border-t border-rule-soft pt-4">
            <p className="eyebrow">Severity of the actionable queue</p>
            <SeverityBar counts={severityCounts} total={metrics?.queue.total_alerts ?? 0} />
          </div>
        </div>

        {/* Regulatory clock — the novel bit, and the most legible thing on screen
            for a non-technical reader. */}
        <Section
          title="Regulatory notification"
          hint={
            notifications?.count
              ? `${notifications.count} incident${notifications.count === 1 ? "" : "s"} on a reporting clock`
              : "Nothing currently meets a reporting threshold"
          }
          actions={
            notifications?.count ? (
              <Link
                href="/compliance"
                className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-accent hover:underline"
              >
                All clocks <ArrowRight className="h-3 w-3" />
              </Link>
            ) : null
          }
        >
          {!notifications ? (
            <div className="h-24 animate-pulse rounded bg-raised" />
          ) : urgent ? (
            <div className="space-y-3.5">
              <PlainEnglish>
                A bank must tell its regulator about a serious incident within hours, not
                days. The clock starts the moment the incident is <em>determined</em> —
                which is the moment this pipeline reached a verdict — so it is counting
                already.
              </PlainEnglish>

              <Link
                href={urgent.kind === "campaign" ? `/campaigns/${urgent.id}` : `/incident/${urgent.id}`}
                className="block rounded border border-rule bg-raised/60 p-3 transition hover:border-accent-deep"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityChip value={urgent.severity} size="xs" />
                  <span className="mono text-[10px] text-faint">{urgent.id}</span>
                  <span className="text-[10px] text-muted">
                    {urgent.alert_count} alert{urgent.alert_count === 1 ? "" : "s"} · reached{" "}
                    {urgent.stage}
                  </span>
                </div>
                <p className="mt-1.5 truncate text-xs font-medium text-ink">{urgent.title}</p>
              </Link>

              <div className="space-y-3">
                {urgent.notification.clocks.slice(0, 2).map((clock) => (
                  <ClockRow key={clock.regime_id} clock={clock} />
                ))}
              </div>

              <p className="text-[10px] leading-relaxed text-faint">{notifications.disclaimer}</p>
            </div>
          ) : (
            <div className="space-y-3">
              <PlainEnglish>
                Nothing in the current queue has progressed far enough to trigger a
                regulatory reporting deadline. Reconnaissance and blocked attempts are
                security events, not reportable incidents.
              </PlainEnglish>
              <div className="flex items-center gap-2 text-xs text-muted">
                <ShieldCheck className="h-4 w-4 text-sev-benign" />
                No notification obligations open
              </div>
            </div>
          )}
        </Section>
      </div>

      {/* ── Supporting metrics ────────────────────────────────────────────────── */}
      {metrics ? (
        <div className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-rule bg-rule sm:grid-cols-3 lg:grid-cols-5">
          <div className="bg-surface">
            <StatTile
              label="Alerts ingested"
              value={metrics.queue.total_alerts}
              sub={`${metrics.queue.actionable} needed a decision`}
            />
          </div>
          <div className="bg-surface">
            <StatTile
              label="Alerts per investigation"
              value={`${metrics.consolidation.ratio}:1`}
              sub={`${metrics.consolidation.campaigns} campaigns, ${metrics.consolidation.standalone} standalone`}
            />
          </div>
          <div className="bg-surface">
            <StatTile
              label="Containment automated"
              value={`${metrics.response.auto_share_pct}%`}
              sub={`${metrics.response.gated_actions} actions held for a human`}
            />
          </div>
          <div className="bg-surface">
            <StatTile
              label="Analyst hours saved"
              value={metrics.time.hours_saved}
              unit="hrs"
              sub="Modelled — assumption shown in the API response"
            />
          </div>
          <div className="bg-surface">
            <StatTile
              label="Pipeline latency"
              value={metrics.time.pipeline_seconds != null ? `${metrics.time.pipeline_seconds}s` : "—"}
              sub={`Control mapped ${metrics.coverage.cis_mapped_pct}% · ATT&CK ${metrics.coverage.attack_mapped_pct}%`}
            />
          </div>
        </div>
      ) : null}

      {/* ── Campaign strip ───────────────────────────────────────────────────── */}
      <CampaignStrip />

      {/* ── Triage queue ─────────────────────────────────────────────────────── */}
      <Section
        title="Triage queue"
        hint="Ordered by severity, then by whether the alert is part of a moving intrusion"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <label className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3 w-3 -translate-y-1/2 text-faint" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="IP, host, account, technique…"
                aria-label="Search the triage queue"
                className="w-52 rounded border border-rule bg-sunk py-1.5 pl-7 pr-2 text-[11px] text-ink placeholder-faint outline-none transition focus:border-accent-deep"
              />
            </label>
            <div className="flex rounded border border-rule bg-sunk p-0.5">
              {(["all", "critical", "high", "medium", "low"] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setSeverityFilter(s)}
                  className={[
                    "rounded px-2 py-1 text-[10px] font-semibold uppercase tracking-wider transition",
                    severityFilter === s ? "bg-raised text-ink" : "text-faint hover:text-muted",
                  ].join(" ")}
                >
                  {s}
                </button>
              ))}
            </div>
            <button
              onClick={() => setShowFiltered((v) => !v)}
              title="Benign and analyst-suppressed alerts are hidden by default"
              className={[
                "rounded border px-2 py-1.5 text-[10px] font-semibold uppercase tracking-wider transition",
                showFiltered
                  ? "border-rule bg-raised text-ink"
                  : "border-rule bg-sunk text-faint hover:text-muted",
              ].join(" ")}
            >
              {showFiltered ? "Showing all" : "Noise hidden"}
            </button>
          </div>
        }
        className="[&>div]:p-0"
      >
        {!incidents ? (
          <div className="space-y-px p-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-14 animate-pulse rounded bg-raised" />
            ))}
          </div>
        ) : queue.length === 0 ? (
          <div className="p-4">
            <EmptyState
              icon={<ShieldCheck className="h-9 w-9" />}
              title={incidents.length === 0 ? "No incidents yet" : "Nothing matches those filters"}
              detail={
                incidents.length === 0
                  ? "Replay a scenario from Attack Simulation to send telemetry through the pipeline."
                  : "Clear the search or widen the severity filter."
              }
            />
          </div>
        ) : (
          <ul className="divide-y divide-rule-soft">
            {queue.map((inc) => (
              <QueueRow key={inc.event_id} incident={inc} />
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

/* ─── Queue row ────────────────────────────────────────────────────────────── */

function QueueRow({ incident }: { incident: Incident }) {
  const det = (incident.detection ?? {}) as Record<string, string | number>;
  const dash = (incident.dashboard ?? {}) as Record<string, string>;
  const cvss = (incident.cvss ?? {}) as Record<string, number | string>;
  const cis = (incident.cis ?? {}) as Record<string, string>;
  const resp = (incident.response ?? {}) as Record<string, unknown>;
  const raw = (incident.raw_event ?? {}) as Record<string, string>;
  const tone = severityTone(det.severity);

  return (
    <li className="group relative">
      <Link
        href={`/incident/${incident.event_id}`}
        className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3 transition hover:bg-raised/50"
      >
        <span className={`absolute left-0 top-0 h-full w-0.5 ${tone.mark} opacity-70`} aria-hidden />

        {/* Identity + what it is */}
        <div className="min-w-0 flex-1 basis-64 space-y-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <SeverityChip value={det.severity} size="xs" />
            <VerdictChip value={det.label} />
            {incident.campaign ? (
              <span className="inline-flex items-center gap-1 rounded border border-sev-critical/35 bg-sev-critical/12 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-sev-critical">
                <GitBranch className="h-2.5 w-2.5" />
                {incident.campaign.campaign_id}
              </span>
            ) : null}
            {resp.requires_human_approval ? (
              <span className="inline-flex items-center gap-1 rounded border border-sev-high/35 bg-sev-high/12 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-sev-high">
                <Timer className="h-2.5 w-2.5" />
                approval
              </span>
            ) : null}
          </div>
          <p className="truncate text-xs font-medium text-ink">
            {dash.alert_title ?? String(det.threat_type ?? "Unclassified activity")}
          </p>
          <p className="mono truncate text-[10px] text-faint">
            {dash.source_ip ?? "—"} → {dash.affected_host ?? "—"}
            {dash.affected_user && dash.affected_user !== "unattributed"
              ? ` · ${dash.affected_user}`
              : ""}
          </p>
        </div>

        {/* Decision factors: technique, control, score, time */}
        <div className="flex shrink-0 flex-wrap items-center gap-x-5 gap-y-1.5 text-[10px]">
          {incident.mitre_attack?.primary?.technique_id ? (
            <span className="mono rounded border border-rule bg-raised px-1.5 py-0.5 text-accent">
              {incident.mitre_attack.primary.technique_id}
            </span>
          ) : null}
          {incident.mitre_attack?.kill_chain_stage ? (
            <span className="text-muted">{incident.mitre_attack.kill_chain_stage}</span>
          ) : null}
          {cis.benchmark_id ? <span className="mono text-faint">{cis.benchmark_id}</span> : null}
          <span className="flex items-baseline gap-1">
            <span className="text-faint">CVSS</span>
            <span className="tabular font-semibold text-ink">{cvss.base_score ?? "—"}</span>
          </span>
          <span className="w-24 text-right text-faint">{formatTimestamp(raw.timestamp)}</span>
          <ArrowRight className="h-3 w-3 text-faint transition group-hover:translate-x-0.5 group-hover:text-muted" />
        </div>
      </Link>
    </li>
  );
}

/* ─── Campaign strip ──────────────────────────────────────────────────────── */

type Campaign = {
  campaign_id: string;
  name: string;
  severity: string;
  incident_count: number;
  furthest_stage: string;
  furthest_stage_order: number;
  progression_pct: number;
  kill_chain: { order: number }[];
  actors: string[];
  assets: string[];
};

function CampaignStrip() {
  const [campaigns, setCampaigns] = useState<Campaign[] | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const res = await fetch("/api/campaigns", { cache: "no-store" });
        const data = await res.json();
        if (alive) setCampaigns(data.campaigns ?? []);
      } catch {
        if (alive) setCampaigns([]);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  if (campaigns === null) {
    return <div className="h-32 animate-pulse rounded-md border border-rule bg-surface" />;
  }
  if (campaigns.length === 0) return null;

  return (
    <Section
      title="Correlated campaigns"
      hint="Alerts that arrived separately but describe one intrusion"
      actions={
        <Link
          href="/campaigns"
          className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-accent hover:underline"
        >
          Open <ArrowRight className="h-3 w-3" />
        </Link>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {campaigns.map((c) => {
          const tone = severityTone(c.severity);
          return (
            <Link
              key={c.campaign_id}
              href={`/campaigns/${c.campaign_id}`}
              className={`group space-y-3 rounded border ${tone.border} bg-raised/50 p-3.5 transition hover:bg-raised`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0 space-y-1.5">
                  <div className="flex items-center gap-1.5">
                    <SeverityChip value={c.severity} size="xs" />
                    <span className="mono text-[10px] text-faint">{c.campaign_id}</span>
                  </div>
                  <p className="line-clamp-2 text-xs font-medium text-ink">{c.name}</p>
                </div>
                <div className="shrink-0 text-right">
                  <p className="figure text-lg font-semibold leading-none text-ink">
                    {c.progression_pct}%
                  </p>
                  <p className="eyebrow mt-1">through</p>
                </div>
              </div>

              <KillChainMeter
                reachedOrders={c.kill_chain.map((s) => s.order)}
                furthestOrder={c.furthest_stage_order}
              />

              <p className="flex items-center justify-between text-[10px] text-muted">
                <span>
                  {c.incident_count} alerts · {c.assets.length} assets
                </span>
                <span className="font-medium text-ink">{c.furthest_stage}</span>
              </p>
            </Link>
          );
        })}
      </div>
    </Section>
  );
}

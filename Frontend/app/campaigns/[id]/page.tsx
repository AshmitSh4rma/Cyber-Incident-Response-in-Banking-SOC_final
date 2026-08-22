"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft, Download, ExternalLink, Link2 } from "lucide-react";

import {
  ClockRow,
  EmptyState,
  KillChainMeter,
  PlainEnglish,
  Section,
  SeverityChip,
  VerdictChip,
  type Clock,
} from "@/components/soc/primitives";
import { formatTimestamp, severityTone, stageSeverity } from "@/lib/severity";

type Incident = {
  event_id: string;
  raw_event?: Record<string, unknown>;
  dashboard?: Record<string, unknown>;
  detection?: Record<string, unknown>;
  cvss?: Record<string, unknown>;
  cis?: Record<string, unknown>;
  mitre_attack?: { kill_chain_stage?: string };
};

type Campaign = {
  campaign_id: string;
  name: string;
  severity: string;
  member_max_severity: string;
  escalated: boolean;
  stages_reached: number;
  incident_count: number;
  first_seen: string;
  last_seen: string;
  furthest_stage: string;
  furthest_stage_order: number;
  progression_pct: number;
  kill_chain: {
    stage: string;
    order: number;
    technique?: string;
    technique_name?: string;
    first_seen?: string;
    event_id?: string;
  }[];
  actors: string[];
  assets: string[];
  accounts: string[];
  techniques: string[];
  linked_by: string[];
  narrative: string;
  incidents?: Incident[];
  notification?: {
    reportable: boolean;
    confidence: string;
    reasons: string[];
    clocks: Clock[];
    disclaimer: string;
  };
};

export default function CampaignDetailPage() {
  const params = useParams<{ id: string }>();
  const campaignId = params?.id ?? "";

  const [campaign, setCampaign] = useState<Campaign | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!campaignId) return;
    let alive = true;
    (async () => {
      try {
        const res = await fetch(`/api/campaigns/${campaignId}`, { cache: "no-store" });
        if (!res.ok) throw new Error(`Backend returned ${res.status}`);
        const data = await res.json();
        if (alive) setCampaign(data);
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [campaignId]);

  if (error) {
    return (
      <div className="mx-auto max-w-3xl space-y-4">
        <BackLink />
        <EmptyState title={`Could not load ${campaignId}`} detail={error} />
      </div>
    );
  }

  if (!campaign) {
    return (
      <div className="mx-auto max-w-[1400px] space-y-4">
        <BackLink />
        <div className="h-72 animate-pulse rounded-md border border-rule bg-surface" />
      </div>
    );
  }

  const tone = severityTone(campaign.severity);
  const incidents = campaign.incidents ?? [];
  const byId = new Map(incidents.map((i) => [i.event_id, i]));
  const clocks = campaign.notification?.clocks ?? [];

  return (
    <div className="mx-auto max-w-[1400px] space-y-5">
      <BackLink />

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className={`relative overflow-hidden rounded-md border ${tone.border} bg-surface p-5`}>
        <span className={`absolute left-0 top-0 h-full w-1 ${tone.mark}`} aria-hidden />
        <div className="flex flex-wrap items-start justify-between gap-4 pl-2">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityChip value={campaign.severity} />
              <span className="mono text-[11px] text-faint">{campaign.campaign_id}</span>
              {campaign.escalated ? (
                <span className="rounded border border-sev-high/35 bg-sev-high/12 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-sev-high">
                  severity escalated
                </span>
              ) : null}
            </div>
            <h1 className="text-xl font-semibold tracking-tight text-ink">{campaign.name}</h1>
            <p className="text-[11px] text-faint">
              {formatTimestamp(campaign.first_seen)} → {formatTimestamp(campaign.last_seen)}
            </p>
          </div>

          <a
            href={`/api/campaigns/${campaign.campaign_id}/report`}
            className="inline-flex shrink-0 items-center gap-1.5 rounded border border-accent-deep bg-accent/10 px-3 py-2 text-[11px] font-semibold text-accent transition hover:bg-accent/20"
          >
            <Download className="h-3.5 w-3.5" />
            Export audit report
          </a>
        </div>

        <div className="mt-5 grid grid-cols-2 gap-px overflow-hidden rounded border border-rule bg-rule sm:grid-cols-4">
          {[
            { label: "Correlated alerts", value: String(campaign.incident_count) },
            { label: "Stages reached", value: `${campaign.stages_reached} of 15` },
            { label: "Lifecycle progression", value: `${campaign.progression_pct}%` },
            { label: "Furthest stage", value: campaign.furthest_stage },
          ].map((s) => (
            <div key={s.label} className="bg-surface px-4 py-3">
              <p className="eyebrow truncate">{s.label}</p>
              <p className="figure mt-1.5 truncate text-base font-semibold text-ink">{s.value}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <div className="space-y-5">
          {/* ── Assessment ──────────────────────────────────────────────────── */}
          <Section title="What happened" hint="Generated from the correlated evidence">
            <p className="max-w-3xl text-sm leading-relaxed text-muted">{campaign.narrative}</p>
          </Section>

          {/* ── Attack chain ────────────────────────────────────────────────── */}
          <Section
            title="Attack lifecycle"
            hint="All 15 ATT&CK tactics; the filled segments are the stages this intrusion reached"
          >
            <div className="space-y-5">
              <KillChainMeter
                reachedOrders={campaign.kill_chain.map((s) => s.order)}
                furthestOrder={campaign.furthest_stage_order}
                showLabels
              />

              <ol className="space-y-0">
                {campaign.kill_chain.map((step, i) => {
                  const incident = step.event_id ? byId.get(step.event_id) : undefined;
                  const isLast = i === campaign.kill_chain.length - 1;
                  const stepTone = severityTone(stageSeverity(step.order));
                  return (
                    <li key={`${step.stage}-${i}`} className="relative flex gap-4 pb-4 last:pb-0">
                      {!isLast ? (
                        <span
                          className="absolute left-[11px] top-6 h-full w-px bg-rule"
                          aria-hidden
                        />
                      ) : null}
                      <span
                        className={`relative z-10 mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-[10px] font-semibold ${stepTone.chip}`}
                      >
                        {i + 1}
                      </span>
                      <div className="min-w-0 flex-1 space-y-1">
                        <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
                          <span className="text-sm font-medium text-ink">{step.stage}</span>
                          {step.technique ? (
                            <span className="mono rounded border border-rule bg-raised px-1.5 py-0.5 text-[10px] text-accent">
                              {step.technique}
                            </span>
                          ) : null}
                          <span className="text-[10px] text-faint">
                            {formatTimestamp(step.first_seen)}
                          </span>
                        </div>
                        {step.technique_name ? (
                          <p className="text-[11px] text-muted">{step.technique_name}</p>
                        ) : null}
                        {incident ? (
                          <Link
                            href={`/incident/${incident.event_id}`}
                            className="mono inline-flex items-center gap-1 text-[10px] text-faint transition hover:text-accent"
                          >
                            {incident.event_id}
                            <ExternalLink className="h-2.5 w-2.5" />
                          </Link>
                        ) : null}
                      </div>
                    </li>
                  );
                })}
              </ol>
            </div>
          </Section>

          {/* ── Member incidents ────────────────────────────────────────────── */}
          <Section title={`Alerts in this campaign (${incidents.length})`} className="[&>div]:p-0">
            <div className="scroll-x">
              <table className="w-full min-w-[720px] text-left text-xs">
                <thead>
                  <tr className="border-b border-rule-soft bg-sunk/60">
                    {["Alert", "Time", "Verdict", "Threat", "Stage", "CVSS", "Control"].map((h) => (
                      <th key={h} className="eyebrow px-4 py-2.5">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((inc) => {
                    const det = (inc.detection ?? {}) as Record<string, string>;
                    const cvss = (inc.cvss ?? {}) as Record<string, number | string>;
                    const cis = (inc.cis ?? {}) as Record<string, string>;
                    const raw = (inc.raw_event ?? {}) as Record<string, string>;
                    return (
                      <tr
                        key={inc.event_id}
                        className="border-b border-rule-soft transition last:border-0 hover:bg-raised/40"
                      >
                        <td className="px-4 py-2.5">
                          <Link
                            href={`/incident/${inc.event_id}`}
                            className="mono text-[10px] text-accent hover:underline"
                          >
                            {inc.event_id}
                          </Link>
                        </td>
                        <td className="px-4 py-2.5 text-muted">{formatTimestamp(raw.timestamp)}</td>
                        <td className="px-4 py-2.5">
                          <VerdictChip value={det.label} />
                        </td>
                        <td className="px-4 py-2.5 text-muted">
                          {String(det.threat_type ?? "").replaceAll("_", " ")}
                        </td>
                        <td className="px-4 py-2.5 text-muted">
                          {inc.mitre_attack?.kill_chain_stage ?? "—"}
                        </td>
                        <td className="tabular px-4 py-2.5 font-semibold text-ink">
                          {cvss.base_score ?? "—"}
                        </td>
                        <td className="mono px-4 py-2.5 text-[10px] text-muted">
                          {cis.benchmark_id ?? "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Section>
        </div>

        {/* ── Right rail ──────────────────────────────────────────────────── */}
        <div className="space-y-5">
          {/* Regulatory clock */}
          <Section
            title="Regulatory notification"
            hint={campaign.notification?.reportable ? "This looks reportable" : "No deadline raised"}
          >
            {campaign.notification?.reportable ? (
              <div className="space-y-4">
                <PlainEnglish>
                  A bank has to tell its regulator about a serious incident within hours.
                  The clock below started when the pipeline reached its verdict.
                </PlainEnglish>
                <div className="space-y-3.5">
                  {clocks.map((clock) => (
                    <ClockRow key={clock.regime_id} clock={clock} />
                  ))}
                </div>
                <div className="space-y-1.5 border-t border-rule-soft pt-3">
                  <p className="eyebrow">Why this is reportable</p>
                  <ul className="space-y-1">
                    {campaign.notification.reasons.map((r) => (
                      <li key={r} className="text-[11px] leading-relaxed text-muted">
                        · {r}
                      </li>
                    ))}
                  </ul>
                </div>
                <p className="text-[10px] leading-relaxed text-faint">
                  {campaign.notification.disclaimer}
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                <p className="text-xs text-muted">
                  This campaign does not meet a notification threshold.
                </p>
                {campaign.notification?.reasons.map((r) => (
                  <p key={r} className="text-[11px] leading-relaxed text-faint">
                    {r}
                  </p>
                ))}
              </div>
            )}
          </Section>

          {/* Why grouped */}
          <Section title="Why these alerts are one campaign" hint="Correlation is deterministic">
            <ul className="space-y-2">
              {campaign.linked_by.map((reason) => (
                <li key={reason} className="flex items-start gap-2 text-[11px] text-muted">
                  <Link2 className="mt-0.5 h-3 w-3 shrink-0 text-accent" />
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </Section>

          {/* Scope */}
          <Section title="Scope">
            <div className="space-y-4">
              <ScopeRow label="Source addresses" values={campaign.actors} />
              <ScopeRow label="Assets involved" values={campaign.assets} />
              {campaign.accounts.length > 0 ? (
                <ScopeRow label="Accounts" values={campaign.accounts} />
              ) : null}
              <ScopeRow label="ATT&CK techniques" values={campaign.techniques} accent />
            </div>
          </Section>
        </div>
      </div>
    </div>
  );
}

function BackLink() {
  return (
    <Link
      href="/campaigns"
      className="inline-flex items-center gap-1.5 text-[11px] text-muted transition hover:text-ink"
    >
      <ArrowLeft className="h-3 w-3" />
      All campaigns
    </Link>
  );
}

function ScopeRow({
  label,
  values,
  accent = false,
}: {
  label: string;
  values: string[];
  accent?: boolean;
}) {
  return (
    <div className="space-y-2">
      <p className="eyebrow">{label}</p>
      {values.length === 0 ? (
        <p className="text-[11px] text-faint">None</p>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {values.map((v) => (
            <span
              key={v}
              className={[
                "mono rounded border px-1.5 py-0.5 text-[10px]",
                accent
                  ? "border-accent-deep/60 bg-accent/10 text-accent"
                  : "border-rule bg-raised text-muted",
              ].join(" ")}
            >
              {v}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

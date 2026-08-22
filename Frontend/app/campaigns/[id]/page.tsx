"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { motion } from "framer-motion";
import { ArrowLeft, Download, ExternalLink, Link2 } from "lucide-react";

import {
  Block,
  ClockRow,
  EmptyState,
  KillChainMeter,
  PlainEnglish,
  Reveal,
  Screen,
  Section,
  SeverityChip,
  Skeleton,
  VerdictChip,
  type Clock,
} from "@/components/soc/primitives";
import { useDetail } from "@/lib/detail";
import { EASE_OUT, riseIn } from "@/lib/motion";
import { formatTimestamp, severityTone, stageSeverity } from "@/lib/severity";

type Incident = {
  event_id: string;
  raw_event?: Record<string, unknown>;
  dashboard?: Record<string, string>;
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
    reasons: string[];
    clocks: Clock[];
    disclaimer: string;
  };
};

export default function CampaignDetailPage() {
  const params = useParams<{ id: string }>();
  const campaignId = params?.id ?? "";
  const { isAnalyst } = useDetail();

  const [campaign, setCampaign] = useState<Campaign | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!campaignId) return;
    let alive = true;
    (async () => {
      try {
        const res = await fetch(`/api/campaigns/${campaignId}`, { cache: "no-store" });
        if (!res.ok) throw new Error(`Service returned ${res.status}`);
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
      <Screen className="max-w-3xl">
        <Block><BackLink /></Block>
        <EmptyState title="Couldn't load this" detail={error} />
      </Screen>
    );
  }

  if (!campaign) {
    return (
      <Screen>
        <Block><BackLink /></Block>
        <Block><Skeleton className="h-72" /></Block>
      </Screen>
    );
  }

  const tone = severityTone(campaign.severity);
  const incidents = campaign.incidents ?? [];
  const byId = new Map(incidents.map((i) => [i.event_id, i]));

  return (
    <Screen>
      <Block><BackLink /></Block>

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <motion.div
        variants={riseIn}
        className={`relative overflow-hidden rounded-lg border ${tone.border} bg-surface p-5`}
      >
        <motion.span
          className={`absolute left-0 top-0 w-1 ${tone.mark}`}
          initial={{ height: 0 }}
          animate={{ height: "100%" }}
          transition={{ duration: 0.5, ease: EASE_OUT }}
          aria-hidden
        />
        <div className="flex flex-wrap items-start justify-between gap-4 pl-2">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityChip value={campaign.severity} />
              {isAnalyst ? <span className="mono text-[11px] text-faint">{campaign.campaign_id}</span> : null}
              {campaign.escalated ? (
                <span
                  className="rounded border border-sev-high/35 bg-sev-high/12 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-sev-high"
                  title={`No single alert was worse than ${campaign.member_max_severity}, but the attack spans ${campaign.stages_reached} stages`}
                >
                  worse together
                </span>
              ) : null}
            </div>
            <h1 className="text-xl font-semibold tracking-tight text-ink">{campaign.name}</h1>
            <p className="text-[11px] text-muted">
              {formatTimestamp(campaign.first_seen)} → {formatTimestamp(campaign.last_seen)}
            </p>
          </div>

          <a
            href={`/api/campaigns/${campaign.campaign_id}/report`}
            className="group inline-flex shrink-0 items-center gap-1.5 rounded-md border border-accent-deep bg-accent/10 px-3 py-2 text-[11px] font-semibold text-accent transition hover:bg-accent/20"
          >
            <Download className="h-3.5 w-3.5 transition group-hover:translate-y-0.5" />
            Download the report
          </a>
        </div>

        <div className="mt-5 grid grid-cols-2 gap-px overflow-hidden rounded border border-rule bg-rule sm:grid-cols-3">
          {[
            { label: "Alerts that were really one attack", value: String(campaign.incident_count) },
            { label: "How far the attacker got", value: campaign.furthest_stage },
            { label: "Through the attack lifecycle", value: `${campaign.progression_pct}%` },
          ].map((s) => (
            <div key={s.label} className="bg-surface px-4 py-3">
              <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-faint">{s.label}</p>
              <p className="figure mt-1.5 truncate text-base font-semibold text-ink">{s.value}</p>
            </div>
          ))}
        </div>
      </motion.div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
        <div className="space-y-4">
          <Section title="What happened">
            <p className="max-w-3xl text-[13px] leading-relaxed text-muted">{campaign.narrative}</p>
          </Section>

          <Section title="How the attack unfolded" hint="Each step was a separate alert at the time">
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
                    <motion.li
                      key={`${step.stage}-${i}`}
                      initial={{ opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.34, delay: 0.15 + i * 0.07, ease: EASE_OUT }}
                      className="relative flex gap-4 pb-4 last:pb-0"
                    >
                      {!isLast ? (
                        <motion.span
                          className="absolute left-[11px] top-6 w-px bg-rule"
                          initial={{ height: 0 }}
                          animate={{ height: "100%" }}
                          transition={{ duration: 0.3, delay: 0.24 + i * 0.07, ease: EASE_OUT }}
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
                          <span className="text-[13px] font-medium text-ink">{step.stage}</span>
                          {isAnalyst && step.technique ? (
                            <span className="mono rounded border border-rule bg-raised px-1.5 py-0.5 text-[10px] text-accent">
                              {step.technique}
                            </span>
                          ) : null}
                          <span className="text-[10px] text-faint">{formatTimestamp(step.first_seen)}</span>
                        </div>
                        {step.technique_name ? (
                          <p className="text-[11px] text-muted">{step.technique_name}</p>
                        ) : null}
                        {incident ? (
                          <Link
                            href={`/incident/${incident.event_id}`}
                            className="inline-flex items-center gap-1 text-[10px] text-faint transition hover:text-accent"
                          >
                            See this alert
                            <ExternalLink className="h-2.5 w-2.5" />
                          </Link>
                        ) : null}
                      </div>
                    </motion.li>
                  );
                })}
              </ol>
            </div>
          </Section>

          <Section title="Details">
            <div className="space-y-2">
              <Reveal label="Why we think these alerts are one attack" count={campaign.linked_by.length}>
                <ul className="space-y-2">
                  {campaign.linked_by.map((reason) => (
                    <li key={reason} className="flex items-start gap-2 text-[11px] text-muted">
                      <Link2 className="mt-0.5 h-3 w-3 shrink-0 text-accent" />
                      <span>{reason}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-3 border-t border-rule-soft pt-3 text-[10px] leading-relaxed text-faint">
                  This grouping is deterministic — the same set of alerts always produces the
                  same result.
                </p>
              </Reveal>

              <Reveal label={`Every alert involved`} count={incidents.length}>
                <div className="scroll-x">
                  <table className="w-full min-w-[620px] text-left text-xs">
                    <thead>
                      <tr className="border-b border-rule-soft">
                        {["Alert", "Time", "What it was", "How far", "Score"].map((h) => (
                          <th key={h} className="pb-2 pr-4 text-[10px] font-semibold uppercase tracking-[0.14em] text-faint">
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {incidents.map((inc) => {
                        const det = (inc.detection ?? {}) as Record<string, string>;
                        const cvss = (inc.cvss ?? {}) as Record<string, number | string>;
                        const raw = (inc.raw_event ?? {}) as Record<string, string>;
                        return (
                          <tr key={inc.event_id} className="border-b border-rule-soft last:border-0">
                            <td className="py-2 pr-4">
                              <Link href={`/incident/${inc.event_id}`} className="text-accent hover:underline">
                                {isAnalyst ? <span className="mono text-[10px]">{inc.event_id}</span> : "Open"}
                              </Link>
                            </td>
                            <td className="py-2 pr-4 text-muted">{formatTimestamp(raw.timestamp)}</td>
                            <td className="py-2 pr-4 text-muted">
                              {String(det.threat_type ?? "").replaceAll("_", " ")}
                            </td>
                            <td className="py-2 pr-4 text-muted">{inc.mitre_attack?.kill_chain_stage ?? "—"}</td>
                            <td className="tabular py-2 font-semibold text-ink">{cvss.base_score ?? "—"}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </Reveal>

              <Reveal label="Systems and accounts involved">
                <div className="space-y-4">
                  <ScopeRow label="Where it came from" values={campaign.actors} />
                  <ScopeRow label="Systems touched" values={campaign.assets} />
                  {campaign.accounts.length > 0 ? (
                    <ScopeRow label="Accounts used" values={campaign.accounts} />
                  ) : null}
                  {isAnalyst ? (
                    <ScopeRow label="ATT&CK techniques" values={campaign.techniques} accent />
                  ) : null}
                </div>
              </Reveal>
            </div>
          </Section>
        </div>

        <div className="space-y-4">
          <Section
            title="Time left to report"
            hint={campaign.notification?.reportable ? "Regulators must be told" : "Nothing to report"}
          >
            {campaign.notification?.reportable ? (
              <div className="space-y-3.5">
                <PlainEnglish>
                  This is serious enough that the regulator has to be told. The countdown
                  started when we worked out what happened.
                </PlainEnglish>
                <ClockRow clock={campaign.notification.clocks[0]} prominent />
                <Reveal label="Other reporting deadlines" count={campaign.notification.clocks.length - 1}>
                  <div className="space-y-3.5">
                    {campaign.notification.clocks.slice(1).map((clock) => (
                      <ClockRow key={clock.regime_id} clock={clock} />
                    ))}
                  </div>
                </Reveal>
                <Reveal label="Why this has to be reported" count={campaign.notification.reasons.length}>
                  <ul className="space-y-1">
                    {campaign.notification.reasons.map((r) => (
                      <li key={r} className="text-[11px] leading-relaxed text-muted">· {r}</li>
                    ))}
                  </ul>
                  <p className="mt-3 border-t border-rule-soft pt-3 text-[10px] leading-relaxed text-faint">
                    {campaign.notification.disclaimer}
                  </p>
                </Reveal>
              </div>
            ) : (
              <div className="space-y-2">
                <p className="text-xs text-muted">This does not meet a reporting threshold.</p>
                {campaign.notification?.reasons.map((r) => (
                  <p key={r} className="text-[11px] leading-relaxed text-faint">{r}</p>
                ))}
              </div>
            )}
          </Section>
        </div>
      </div>
    </Screen>
  );
}

function BackLink() {
  return (
    <Link
      href="/campaigns"
      className="group inline-flex items-center gap-1.5 text-[11px] text-muted transition hover:text-ink"
    >
      <ArrowLeft className="h-3 w-3 transition group-hover:-translate-x-0.5" />
      All attacks
    </Link>
  );
}

function ScopeRow({ label, values, accent = false }: { label: string; values: string[]; accent?: boolean }) {
  return (
    <div className="space-y-2">
      <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-faint">{label}</p>
      {values.length === 0 ? (
        <p className="text-[11px] text-faint">None</p>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {values.map((v) => (
            <span
              key={v}
              className={[
                "mono rounded border px-1.5 py-0.5 text-[10px]",
                accent ? "border-accent-deep/60 bg-accent/10 text-accent" : "border-rule bg-raised text-muted",
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

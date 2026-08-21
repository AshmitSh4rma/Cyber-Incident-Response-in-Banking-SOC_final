"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft, Download, ExternalLink, Link2 } from "lucide-react";

import KillChainRail from "@/components/soc/KillChainRail";
import { formatTimestamp, severityTone, verdictTone } from "@/lib/severity";

type Incident = {
  event_id: string;
  raw_event?: Record<string, unknown>;
  dashboard?: Record<string, unknown>;
  detection?: Record<string, unknown>;
  cvss?: Record<string, unknown>;
  cis?: Record<string, unknown>;
  mitre_attack?: {
    primary?: { technique_id?: string; technique_name?: string; url?: string; tactic_name?: string };
    kill_chain_stage?: string;
  };
};

type Campaign = {
  campaign_id: string;
  name: string;
  severity: string;
  member_max_severity: string;
  escalated: boolean;
  stages_reached: number;
  incident_count: number;
  confidence: number;
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
      <div className="space-y-4">
        <BackLink />
        <div className="rounded border border-red-900/50 bg-red-950/20 px-4 py-3 text-xs text-red-300">
          Could not load {campaignId}: {error}
        </div>
      </div>
    );
  }

  if (!campaign) {
    return (
      <div className="space-y-4">
        <BackLink />
        <div className="h-64 animate-pulse rounded border border-slate-800 bg-slate-900/60" />
      </div>
    );
  }

  const tone = severityTone(campaign.severity);
  const incidents = campaign.incidents ?? [];
  const byId = new Map(incidents.map((i) => [i.event_id, i]));

  return (
    <div className="space-y-6">
      <BackLink />

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className={`relative overflow-hidden rounded border ${tone.border} bg-slate-900/70 p-6`}>
        <div className={`absolute left-0 top-0 h-full w-1 ${tone.rail}`} />
        <div className="flex flex-wrap items-start justify-between gap-4 pl-2">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`inline-flex items-center rounded border px-2 py-0.5 text-[9px] font-extrabold uppercase tracking-widest ${tone.chip}`}
              >
                {campaign.severity}
              </span>
              <span className="mono text-[11px] text-slate-500">{campaign.campaign_id}</span>
              {campaign.escalated && (
                <span className="rounded border border-amber-800/50 bg-amber-950/30 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-amber-400">
                  severity escalated
                </span>
              )}
            </div>
            <h1 className="text-xl font-bold tracking-tight text-slate-100">{campaign.name}</h1>
            <p className="text-[11px] text-slate-500">
              {formatTimestamp(campaign.first_seen)} → {formatTimestamp(campaign.last_seen)}
            </p>
          </div>

          <a
            href={`/api/campaigns/${campaign.campaign_id}/report`}
            className="inline-flex shrink-0 items-center gap-1.5 rounded border border-cyan-800/60 bg-cyan-950/30 px-3 py-2 text-[11px] font-semibold text-cyan-300 transition hover:bg-cyan-950/50"
          >
            <Download className="h-3.5 w-3.5" />
            Export audit report
          </a>
        </div>

        {/* Headline numbers */}
        <div className="mt-5 grid grid-cols-2 gap-px overflow-hidden rounded border border-slate-800 bg-slate-800 sm:grid-cols-4">
          {[
            { label: "Correlated alerts", value: campaign.incident_count },
            { label: "Stages reached", value: `${campaign.stages_reached} of 15` },
            { label: "Lifecycle progression", value: `${campaign.progression_pct}%` },
            { label: "Furthest stage", value: campaign.furthest_stage },
          ].map((s) => (
            <div key={s.label} className="bg-slate-900/90 px-4 py-3">
              <p className="eyebrow truncate">{s.label}</p>
              <p className="tabular mt-1 truncate text-base font-semibold text-slate-100">{s.value}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ── Assessment ─────────────────────────────────────────────────────── */}
      <section className="rounded border border-slate-800 bg-slate-900/60 p-5">
        <p className="eyebrow mb-2">Assessment</p>
        <p className="max-w-3xl text-sm leading-relaxed text-slate-300">{campaign.narrative}</p>
      </section>

      {/* ── Kill chain ─────────────────────────────────────────────────────── */}
      <section className="space-y-4 rounded border border-slate-800 bg-slate-900/60 p-5">
        <p className="eyebrow">Attack lifecycle</p>
        <KillChainRail chain={campaign.kill_chain} furthestOrder={campaign.furthest_stage_order} />

        {/* Chain steps as a vertical timeline */}
        <ol className="mt-2 space-y-0">
          {campaign.kill_chain.map((step, i) => {
            const incident = step.event_id ? byId.get(step.event_id) : undefined;
            const isLast = i === campaign.kill_chain.length - 1;
            return (
              <li key={`${step.stage}-${i}`} className="relative flex gap-4 pb-4">
                {!isLast && <span className="absolute left-[11px] top-6 h-full w-px bg-slate-700" />}
                <span
                  className={[
                    "relative z-10 mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-[10px] font-bold",
                    step.order >= 14
                      ? "border-red-700 bg-red-950 text-red-300"
                      : step.order >= 11
                        ? "border-orange-700 bg-orange-950 text-orange-300"
                        : "border-slate-700 bg-slate-800 text-slate-300",
                  ].join(" ")}
                >
                  {i + 1}
                </span>
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
                    <span className="text-sm font-semibold text-slate-100">{step.stage}</span>
                    {step.technique && (
                      <span className="mono rounded border border-slate-700/60 bg-slate-800/60 px-1.5 py-0.5 text-[10px] text-cyan-300">
                        {step.technique}
                      </span>
                    )}
                    <span className="text-[10px] text-slate-500">{formatTimestamp(step.first_seen)}</span>
                  </div>
                  {step.technique_name && (
                    <p className="text-[11px] text-slate-400">{step.technique_name}</p>
                  )}
                  {incident && (
                    <Link
                      href={`/incident/${incident.event_id}`}
                      className="inline-flex items-center gap-1 text-[10px] text-slate-500 transition hover:text-cyan-300"
                    >
                      <span className="mono">{incident.event_id}</span>
                      <ExternalLink className="h-2.5 w-2.5" />
                    </Link>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      </section>

      {/* ── Why these are one campaign ─────────────────────────────────────── */}
      <section className="rounded border border-slate-800 bg-slate-900/60 p-5">
        <p className="eyebrow mb-3">Correlation basis</p>
        <p className="mb-3 text-[11px] text-slate-500">
          These alerts were grouped for the following reasons. Correlation is
          deterministic — the same alerts always produce the same grouping.
        </p>
        <ul className="space-y-1.5">
          {campaign.linked_by.map((reason) => (
            <li key={reason} className="flex items-start gap-2 text-xs text-slate-300">
              <Link2 className="mt-0.5 h-3 w-3 shrink-0 text-cyan-500" />
              <span>{reason}</span>
            </li>
          ))}
        </ul>
      </section>

      {/* ── Scope ──────────────────────────────────────────────────────────── */}
      <section className="grid gap-4 sm:grid-cols-3">
        <ScopeCard title="Source addresses" values={campaign.actors} />
        <ScopeCard title="Assets involved" values={campaign.assets} />
        <ScopeCard title="ATT&CK techniques" values={campaign.techniques} accent />
      </section>

      {/* ── Member incidents ───────────────────────────────────────────────── */}
      <section className="rounded border border-slate-800 bg-slate-900/60">
        <div className="border-b border-slate-800 px-5 py-3">
          <p className="eyebrow">Member incidents ({incidents.length})</p>
        </div>
        <div className="scroll-x">
          <table className="w-full min-w-[760px] text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/50">
                {["Incident", "Time", "Verdict", "Threat", "Stage", "CVSS", "Control"].map((h) => (
                  <th key={h} className="eyebrow px-4 py-2.5 font-semibold">
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
                const t = severityTone(det.severity);
                return (
                  <tr
                    key={inc.event_id}
                    className="border-b border-slate-800/60 transition last:border-0 hover:bg-slate-800/30"
                  >
                    <td className="px-4 py-2.5">
                      <Link
                        href={`/incident/${inc.event_id}`}
                        className="mono text-[10px] text-cyan-400 hover:underline"
                      >
                        {inc.event_id}
                      </Link>
                    </td>
                    <td className="px-4 py-2.5 text-slate-400">{formatTimestamp(raw.timestamp)}</td>
                    <td className="px-4 py-2.5">
                      <span
                        className={`rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase ${verdictTone(det.label)}`}
                      >
                        {det.label}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-slate-300">
                      {String(det.threat_type ?? "").replaceAll("_", " ")}
                    </td>
                    <td className="px-4 py-2.5 text-slate-400">
                      {inc.mitre_attack?.kill_chain_stage ?? "—"}
                    </td>
                    <td className={`tabular px-4 py-2.5 font-semibold ${t.text}`}>
                      {cvss.base_score ?? "—"}
                    </td>
                    <td className="mono px-4 py-2.5 text-[10px] text-slate-400">
                      {cis.benchmark_id ?? "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function BackLink() {
  return (
    <Link
      href="/campaigns"
      className="inline-flex items-center gap-1.5 text-[11px] text-slate-500 transition hover:text-slate-300"
    >
      <ArrowLeft className="h-3 w-3" />
      All campaigns
    </Link>
  );
}

function ScopeCard({ title, values, accent = false }: { title: string; values: string[]; accent?: boolean }) {
  return (
    <div className="rounded border border-slate-800 bg-slate-900/60 p-4">
      <p className="eyebrow mb-2.5">{title}</p>
      {values.length === 0 ? (
        <p className="text-[11px] text-slate-600">None</p>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {values.map((v) => (
            <span
              key={v}
              className={[
                "mono rounded border px-1.5 py-0.5 text-[10px]",
                accent
                  ? "border-cyan-900/60 bg-cyan-950/30 text-cyan-300"
                  : "border-slate-700/60 bg-slate-800/50 text-slate-300",
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

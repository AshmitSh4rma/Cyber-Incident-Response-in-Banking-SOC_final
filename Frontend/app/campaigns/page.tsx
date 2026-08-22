"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, GitBranch, KeyRound, Server, Users } from "lucide-react";

import {
  EmptyState,
  KillChainMeter,
  PlainEnglish,
  SeverityChip,
} from "@/components/soc/primitives";
import { formatTimestamp, severityTone } from "@/lib/severity";

type Campaign = {
  campaign_id: string;
  name: string;
  severity: string;
  member_max_severity: string;
  escalated: boolean;
  incident_count: number;
  first_seen: string;
  last_seen: string;
  furthest_stage: string;
  furthest_stage_order: number;
  progression_pct: number;
  stages_reached: number;
  kill_chain: { stage: string; order: number }[];
  actors: string[];
  assets: string[];
  accounts: string[];
  notification?: { reportable: boolean; tightest?: { authority: string } | null };
};

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<Campaign[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const res = await fetch("/api/campaigns", { cache: "no-store" });
        if (!res.ok) throw new Error(`Backend returned ${res.status}`);
        const data = await res.json();
        if (alive) setCampaigns(data.campaigns ?? []);
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  return (
    <div className="mx-auto max-w-[1400px] space-y-5">
      <header className="space-y-3">
        <p className="eyebrow">Campaign correlation</p>
        <h1 className="text-2xl font-semibold tracking-tight text-ink">
          One intrusion, many alerts
        </h1>
        <PlainEnglish>
          Alerts arrive one at a time; an intruder does not. A campaign is a set of
          alerts that turned out to describe the same attacker moving through the
          network — including the step most tools miss, where a machine that was
          attacked becomes the source of the next alert.
        </PlainEnglish>
      </header>

      {error ? (
        <EmptyState
          icon={<GitBranch className="h-9 w-9" />}
          title="Could not load campaigns"
          detail={`${error}. Start the backend with \`uvicorn api_server:app --port 8000\`.`}
        />
      ) : null}

      {!campaigns && !error ? (
        <div className="space-y-4">
          {Array.from({ length: 2 }).map((_, i) => (
            <div key={i} className="h-44 animate-pulse rounded-md border border-rule bg-surface" />
          ))}
        </div>
      ) : null}

      {campaigns && campaigns.length === 0 ? (
        <EmptyState
          icon={<GitBranch className="h-9 w-9" />}
          title="No campaigns correlated"
          detail="Correlation needs at least two related alerts. Replay the multi-stage scenario from Attack Simulation to see a full chain reconstructed."
        />
      ) : null}

      <div className="space-y-4">
        {campaigns?.map((c) => {
          const tone = severityTone(c.severity);
          return (
            <Link
              key={c.campaign_id}
              href={`/campaigns/${c.campaign_id}`}
              className={`group relative block overflow-hidden rounded-md border ${tone.border} bg-surface transition hover:bg-raised/40`}
            >
              <span className={`absolute left-0 top-0 h-full w-0.5 ${tone.mark}`} aria-hidden />

              <div className="space-y-4 p-5 pl-6">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0 space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityChip value={c.severity} />
                      <span className="mono text-[10px] text-faint">{c.campaign_id}</span>
                      {c.escalated ? (
                        <span
                          className="rounded border border-sev-high/35 bg-sev-high/12 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-sev-high"
                          title={`Individual alerts peaked at ${c.member_max_severity}; raised because the chain spans ${c.stages_reached} stages`}
                        >
                          escalated
                        </span>
                      ) : null}
                      {c.notification?.reportable ? (
                        <span className="rounded border border-sev-critical/35 bg-sev-critical/12 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-sev-critical">
                          reportable
                        </span>
                      ) : null}
                    </div>
                    <h2 className="text-base font-semibold text-ink">{c.name}</h2>
                    <p className="text-[11px] text-faint">
                      {formatTimestamp(c.first_seen)} → {formatTimestamp(c.last_seen)}
                    </p>
                  </div>

                  <div className="flex shrink-0 items-start gap-6 text-right">
                    <div>
                      <p className="eyebrow">Alerts</p>
                      <p className="figure mt-1 text-xl font-semibold leading-none text-ink">
                        {c.incident_count}
                      </p>
                    </div>
                    <div>
                      <p className="eyebrow">Lifecycle</p>
                      <p className="figure mt-1 text-xl font-semibold leading-none text-ink">
                        {c.progression_pct}%
                      </p>
                    </div>
                    <ArrowRight className="mt-2 h-4 w-4 text-faint transition group-hover:translate-x-0.5 group-hover:text-muted" />
                  </div>
                </div>

                <KillChainMeter
                  reachedOrders={c.kill_chain.map((s) => s.order)}
                  furthestOrder={c.furthest_stage_order}
                  showLabels
                />

                <div className="scroll-x pt-1">
                  <div className="flex items-center gap-1.5 whitespace-nowrap text-[11px]">
                    {c.kill_chain.map((s, i) => (
                      <span key={`${s.stage}-${i}`} className="flex items-center gap-1.5">
                        {i > 0 ? <span className="text-faint">→</span> : null}
                        <span className="rounded border border-rule bg-raised px-1.5 py-0.5 text-muted">
                          {s.stage}
                        </span>
                      </span>
                    ))}
                    <span className="ml-1 text-faint">
                      · stopped at {c.furthest_stage}
                    </span>
                  </div>
                </div>

                <div className="flex flex-wrap gap-x-6 gap-y-2 border-t border-rule-soft pt-3 text-[10px] text-muted">
                  <span className="flex items-center gap-1.5">
                    <Users className="h-3 w-3 text-faint" />
                    {c.actors.length} source{c.actors.length === 1 ? "" : "s"}
                    <span className="mono text-ink">{c.actors.slice(0, 2).join(", ")}</span>
                    {c.actors.length > 2 ? <span className="text-faint">+{c.actors.length - 2}</span> : null}
                  </span>
                  <span className="flex items-center gap-1.5">
                    <Server className="h-3 w-3 text-faint" />
                    {c.assets.length} asset{c.assets.length === 1 ? "" : "s"}
                    <span className="mono text-ink">{c.assets.slice(0, 2).join(", ")}</span>
                    {c.assets.length > 2 ? <span className="text-faint">+{c.assets.length - 2}</span> : null}
                  </span>
                  {c.accounts.length > 0 ? (
                    <span className="flex items-center gap-1.5">
                      <KeyRound className="h-3 w-3 text-faint" />
                      <span className="mono text-ink">{c.accounts.join(", ")}</span>
                    </span>
                  ) : null}
                </div>
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
}

"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, GitBranch, Users, Server, KeyRound } from "lucide-react";

import KillChainRail from "@/components/soc/KillChainRail";
import { formatTimestamp, severityTone } from "@/lib/severity";

type Campaign = {
  campaign_id: string;
  name: string;
  severity: string;
  member_max_severity: string;
  escalated: boolean;
  incident_count: number;
  confidence: number;
  first_seen: string;
  last_seen: string;
  furthest_stage: string;
  furthest_stage_order: number;
  progression_pct: number;
  stages_reached: number;
  kill_chain: { stage: string; order: number; technique?: string; technique_name?: string; first_seen?: string }[];
  actors: string[];
  assets: string[];
  accounts: string[];
  techniques: string[];
  linked_by: string[];
  narrative: string;
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
      } catch {
        // Static fallback for a backend-less demo.
        try {
          const res = await fetch("/frontend_output.json", { cache: "no-store" });
          const data = await res.json();
          if (alive) setCampaigns(data.campaigns ?? []);
        } catch (e) {
          if (alive) setError(e instanceof Error ? e.message : String(e));
        }
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="space-y-2">
        <p className="eyebrow">Layer 2.5 · Campaign correlation</p>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">
          Correlated Attack Campaigns
        </h1>
        <p className="max-w-2xl text-xs leading-relaxed text-slate-400">
          Alerts arrive one at a time; intrusions do not. Campaigns group alerts that
          describe the same activity — including the hop most correlation misses,
          where a host that was attacked becomes the source of the next alert — and
          report how far through the ATT&amp;CK lifecycle the intruder actually got.
        </p>
      </div>

      {error && (
        <div className="rounded border border-red-900/50 bg-red-950/20 px-4 py-3 text-xs text-red-300">
          Could not load campaigns: {error}
        </div>
      )}

      {!campaigns && !error && (
        <div className="space-y-3">
          {Array.from({ length: 2 }).map((_, i) => (
            <div key={i} className="h-40 animate-pulse rounded border border-slate-800 bg-slate-900/60" />
          ))}
        </div>
      )}

      {campaigns && campaigns.length === 0 && (
        <div className="flex flex-col items-center justify-center rounded border border-dashed border-slate-800 bg-slate-950/40 py-16 text-center">
          <GitBranch className="mb-3 h-9 w-9 text-slate-700" />
          <p className="text-sm font-semibold text-slate-300">No campaigns correlated</p>
          <p className="mt-1 max-w-sm text-xs text-slate-500">
            Correlation needs at least two related alerts. Run the pipeline over the
            demo attack scenario to see a full chain reconstructed.
          </p>
        </div>
      )}

      {campaigns?.map((c) => {
        const tone = severityTone(c.severity);
        return (
          <Link
            key={c.campaign_id}
            href={`/campaigns/${c.campaign_id}`}
            className={`group relative block overflow-hidden rounded border ${tone.border} bg-slate-900/60 transition hover:bg-slate-900/90`}
          >
            <div className={`absolute left-0 top-0 h-full w-0.5 ${tone.rail} opacity-80`} />

            <div className="space-y-4 p-5 pl-6">
              {/* Title row */}
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`inline-flex items-center rounded border px-2 py-0.5 text-[9px] font-extrabold uppercase tracking-widest ${tone.chip}`}
                    >
                      {c.severity}
                    </span>
                    <span className="mono text-[10px] text-slate-500">{c.campaign_id}</span>
                    {c.escalated && (
                      <span
                        className="rounded border border-amber-800/50 bg-amber-950/30 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-amber-400"
                        title={`Members peaked at ${c.member_max_severity}; raised because the chain spans ${c.stages_reached} stages`}
                      >
                        escalated
                      </span>
                    )}
                  </div>
                  <h2 className="text-base font-semibold text-slate-100">{c.name}</h2>
                </div>

                <div className="flex shrink-0 items-center gap-5 text-right">
                  <div>
                    <p className="eyebrow">Alerts</p>
                    <p className="tabular text-lg font-semibold text-slate-100">{c.incident_count}</p>
                  </div>
                  <div>
                    <p className="eyebrow">Progression</p>
                    <p className={`tabular text-lg font-semibold ${tone.text}`}>{c.progression_pct}%</p>
                  </div>
                  <ArrowRight className="h-4 w-4 text-slate-600 transition group-hover:translate-x-0.5 group-hover:text-slate-300" />
                </div>
              </div>

              {/* Kill chain rail — the whole lifecycle, with reached stages lit */}
              <KillChainRail chain={c.kill_chain} furthestOrder={c.furthest_stage_order} />

              {/* Chain as text */}
              <div className="scroll-x">
                <div className="flex items-center gap-1.5 whitespace-nowrap text-[11px]">
                  {c.kill_chain.map((s, i) => (
                    <span key={`${s.stage}-${i}`} className="flex items-center gap-1.5">
                      {i > 0 && <span className="text-slate-600">→</span>}
                      <span className="rounded border border-slate-700/60 bg-slate-800/50 px-1.5 py-0.5 text-slate-300">
                        {s.stage}
                      </span>
                    </span>
                  ))}
                </div>
              </div>

              {/* Scope */}
              <div className="flex flex-wrap gap-x-6 gap-y-2 border-t border-slate-800 pt-3 text-[10px] text-slate-500">
                <span className="flex items-center gap-1.5">
                  <Users className="h-3 w-3" />
                  {c.actors.length} source{c.actors.length === 1 ? "" : "s"}
                  <span className="mono text-slate-400">{c.actors.slice(0, 2).join(", ")}</span>
                  {c.actors.length > 2 && <span>+{c.actors.length - 2}</span>}
                </span>
                <span className="flex items-center gap-1.5">
                  <Server className="h-3 w-3" />
                  {c.assets.length} asset{c.assets.length === 1 ? "" : "s"}
                  <span className="mono text-slate-400">{c.assets.slice(0, 2).join(", ")}</span>
                  {c.assets.length > 2 && <span>+{c.assets.length - 2}</span>}
                </span>
                {c.accounts.length > 0 && (
                  <span className="flex items-center gap-1.5">
                    <KeyRound className="h-3 w-3" />
                    <span className="mono text-slate-400">{c.accounts.join(", ")}</span>
                  </span>
                )}
                <span>
                  {formatTimestamp(c.first_seen)} → {formatTimestamp(c.last_seen)}
                </span>
              </div>
            </div>
          </Link>
        );
      })}
    </div>
  );
}

"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, ShieldAlert } from "lucide-react";

export type Metrics = {
  queue: {
    total_alerts: number;
    benign_filtered: number;
    analyst_suppressed: number;
    actionable: number;
    severity: Record<string, number>;
  };
  consolidation: {
    actionable_alerts: number;
    investigations: number;
    campaigns: number;
    standalone: number;
    ratio: number;
    headline: string;
  };
  coverage: {
    cis_mapped_pct: number;
    attack_mapped_pct: number;
    cvss_scored_pct: number;
  };
  time: {
    pipeline_seconds: number | null;
    hours_saved: number;
    minutes_saved: number;
    assumptions: {
      manual_triage_minutes_per_alert: number;
      review_minutes_per_incident: number;
      note: string;
    };
  };
  feedback_loop: {
    false_positives_marked: number;
    alerts_suppressed: number;
  };
  response: {
    gated_actions: number;
    auto_executable_actions: number;
    auto_share_pct: number;
  };
  worst_campaign: {
    campaign_id: string;
    name: string;
    severity: string;
    furthest_stage: string;
    progression_pct: number;
    incident_count: number;
  } | null;
};

function Stat({
  label,
  value,
  unit,
  sub,
  emphasis = false,
}: {
  label: string;
  value: string | number;
  unit?: string;
  sub?: string;
  emphasis?: boolean;
}) {
  return (
    <div className="min-w-0 px-4 py-3">
      <p className="eyebrow truncate">{label}</p>
      <p className="mt-1 flex items-baseline gap-1">
        <span
          className={[
            "tabular font-semibold leading-none",
            emphasis ? "text-2xl text-cyan-300" : "text-2xl text-slate-100",
          ].join(" ")}
        >
          {value}
        </span>
        {unit ? <span className="text-[11px] text-slate-500">{unit}</span> : null}
      </p>
      {sub ? <p className="mt-1 truncate text-[10px] text-slate-500">{sub}</p> : null}
    </div>
  );
}

/**
 * The value the pipeline delivered, computed from stored state.
 *
 * The consolidation number leads because it is the one an analyst feels: how
 * many things they actually have to look at versus how many alerts arrived.
 */
export default function MetricsHeader() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const res = await fetch("/api/metrics", { cache: "no-store" });
        if (!res.ok) throw new Error(String(res.status));
        const data = (await res.json()) as Metrics;
        if (alive) setMetrics(data);
      } catch {
        // Static fallback so the header still renders with no backend.
        try {
          const res = await fetch("/soc_metrics.json", { cache: "no-store" });
          const data = (await res.json()) as Metrics;
          if (alive) setMetrics(data);
        } catch {
          if (alive) setFailed(true);
        }
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  if (failed) {
    return (
      <div className="rounded border border-slate-800 bg-slate-900/40 px-4 py-3 text-xs text-slate-500">
        Metrics unavailable — start the backend with{" "}
        <code className="mono text-slate-400">uvicorn api_server:app --port 8000</code>
      </div>
    );
  }

  if (!metrics) {
    return (
      <div className="grid animate-pulse grid-cols-2 gap-px rounded border border-slate-800 bg-slate-800 lg:grid-cols-5">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="h-[74px] bg-slate-900/80" />
        ))}
      </div>
    );
  }

  const { queue, consolidation, coverage, time, response, worst_campaign } = metrics;
  const noiseRemoved = queue.benign_filtered + queue.analyst_suppressed;

  return (
    <div className="space-y-3">
      {/* The headline: what an analyst actually has to work through. */}
      <div className="grid grid-cols-2 gap-px overflow-hidden rounded border border-slate-800 bg-slate-800 sm:grid-cols-3 lg:grid-cols-5">
        <div className="bg-slate-900/90">
          <Stat
            label="Alerts ingested"
            value={queue.total_alerts}
            sub={`${noiseRemoved} filtered as benign or suppressed`}
          />
        </div>
        <div className="bg-slate-900/90">
          <Stat
            label="Investigations"
            value={consolidation.investigations}
            emphasis
            sub={`from ${consolidation.actionable_alerts} actionable alerts · ${consolidation.ratio}:1`}
          />
        </div>
        <div className="bg-slate-900/90">
          <Stat
            label="Campaigns correlated"
            value={consolidation.campaigns}
            sub={`${consolidation.standalone} standalone incidents`}
          />
        </div>
        <div className="bg-slate-900/90">
          <Stat
            label="Containment automated"
            value={`${response.auto_share_pct}%`}
            sub={`${response.gated_actions} actions held for approval`}
          />
        </div>
        <div className="bg-slate-900/90">
          <Stat
            label="Analyst time saved"
            value={time.hours_saved}
            unit="hrs"
            sub={`modelled at ${time.assumptions.manual_triage_minutes_per_alert} min/alert manual`}
          />
        </div>
      </div>

      {/* Coverage + latency, secondary weight. */}
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 px-1 text-[10px] text-slate-500">
        <span>
          CIS control mapped{" "}
          <span className="tabular font-semibold text-slate-300">{coverage.cis_mapped_pct}%</span>
        </span>
        <span>
          ATT&amp;CK mapped{" "}
          <span className="tabular font-semibold text-slate-300">{coverage.attack_mapped_pct}%</span>
        </span>
        <span>
          CVSS scored{" "}
          <span className="tabular font-semibold text-slate-300">{coverage.cvss_scored_pct}%</span>
        </span>
        {time.pipeline_seconds != null && (
          <span>
            last run{" "}
            <span className="tabular font-semibold text-slate-300">{time.pipeline_seconds}s</span>
          </span>
        )}
        {metrics.feedback_loop.false_positives_marked > 0 && (
          <span>
            suppression rules{" "}
            <span className="tabular font-semibold text-slate-300">
              {metrics.feedback_loop.false_positives_marked}
            </span>
          </span>
        )}
      </div>

      {/* Worst campaign gets its own banner — it is the thing to look at next. */}
      {worst_campaign && (
        <Link
          href={`/campaigns/${worst_campaign.campaign_id}`}
          className="group flex items-center gap-3 rounded border border-red-900/40 bg-red-950/20 px-4 py-2.5 transition hover:border-red-800/60 hover:bg-red-950/30"
        >
          <ShieldAlert className="h-4 w-4 shrink-0 text-red-400" />
          <div className="min-w-0 flex-1">
            <p className="truncate text-xs font-semibold text-slate-100">
              {worst_campaign.name}
            </p>
            <p className="mt-0.5 text-[10px] text-slate-400">
              <span className="mono text-red-300">{worst_campaign.campaign_id}</span> ·{" "}
              {worst_campaign.incident_count} correlated alerts · reached{" "}
              <span className="font-semibold text-red-300">{worst_campaign.furthest_stage}</span> (
              {worst_campaign.progression_pct}% of the attack lifecycle)
            </p>
          </div>
          <ArrowRight className="h-3.5 w-3.5 shrink-0 text-slate-500 transition group-hover:translate-x-0.5 group-hover:text-slate-300" />
        </Link>
      )}
    </div>
  );
}

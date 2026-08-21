"use client";

import Link from "next/link";
import { ArrowRight, GitBranch } from "lucide-react";
import { EventPipeline } from "@/lib/mockData";
import { severityTone } from "@/lib/severity";

/**
 * Shown when an incident belongs to a correlated campaign.
 *
 * This is the most important context an analyst can have on an incident page:
 * the difference between "one web request was blocked" and "this is step three
 * of an intrusion that reached the database" changes what they do next.
 */
export default function CampaignBanner({ pipeline }: { pipeline: EventPipeline | null }) {
  const campaign = pipeline?.campaign;
  if (!campaign?.campaign_id) return null;

  const tone = severityTone(campaign.severity);

  return (
    <Link
      href={`/campaigns/${campaign.campaign_id}`}
      className={`group flex items-center gap-3 rounded border ${tone.border} bg-slate-900/70 px-4 py-2.5 transition hover:bg-slate-900`}
    >
      <GitBranch className={`h-4 w-4 shrink-0 ${tone.text}`} />
      <div className="min-w-0 flex-1">
        <p className="text-xs font-semibold text-slate-100">
          Part of a correlated campaign — not an isolated alert
        </p>
        <p className="mt-0.5 truncate text-[10px] text-slate-400">
          <span className="mono">{campaign.campaign_id}</span> · {campaign.name} ·{" "}
          {campaign.incident_count} alerts · reached{" "}
          <span className={`font-semibold ${tone.text}`}>{campaign.furthest_stage}</span> (
          {campaign.progression_pct}% of the lifecycle)
        </p>
      </div>
      <ArrowRight className="h-3.5 w-3.5 shrink-0 text-slate-500 transition group-hover:translate-x-0.5 group-hover:text-slate-300" />
    </Link>
  );
}

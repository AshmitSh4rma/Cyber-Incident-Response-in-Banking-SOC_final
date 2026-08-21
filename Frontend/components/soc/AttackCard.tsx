"use client";

import { ExternalLink } from "lucide-react";
import { EventPipeline } from "@/lib/mockData";
import { ATTACK_TACTICS, stageTone } from "@/lib/severity";

/**
 * ATT&CK classification for one incident, with the tactic shown in the context
 * of the whole lifecycle so "Initial Access" reads as early and "Exfiltration"
 * reads as late.
 */
export default function AttackCard({ pipeline }: { pipeline: EventPipeline | null }) {
  const attack = pipeline?.mitre_attack;
  const primary = attack?.primary;

  if (!primary?.technique_id) {
    return (
      <div className="rounded border border-slate-800 bg-slate-900/60 p-5">
        <p className="eyebrow mb-2">MITRE ATT&amp;CK</p>
        <p className="text-xs text-slate-500">
          No technique mapped. The detection did not match a threat pattern with a
          known ATT&amp;CK equivalent.
        </p>
      </div>
    );
  }

  const order = attack?.kill_chain_order ?? 0;
  const others = (attack?.techniques ?? []).filter((t) => t.technique_id !== primary.technique_id);

  return (
    <div className="space-y-4 rounded border border-slate-800 bg-slate-900/60 p-5">
      <div className="flex items-start justify-between gap-3">
        <p className="eyebrow">MITRE ATT&amp;CK</p>
        <span className="eyebrow">Enterprise</span>
      </div>

      {/* Primary technique */}
      <div className="space-y-1.5">
        <a
          href={primary.url}
          target="_blank"
          rel="noopener noreferrer"
          className="mono inline-flex items-center gap-1.5 text-base font-bold text-cyan-300 transition hover:text-cyan-200"
        >
          {primary.technique_id}
          <ExternalLink className="h-3 w-3" />
        </a>
        <p className="text-sm font-semibold text-slate-100">{primary.technique_name}</p>
        <p className="text-[11px] text-slate-400">
          Tactic: <span className={stageTone(order)}>{primary.tactic_name}</span>
        </p>
      </div>

      {/* Where this sits in the lifecycle */}
      <div className="space-y-2">
        <p className="eyebrow">Position in attack lifecycle</p>
        <div className="flex items-end gap-[2px]">
          {ATTACK_TACTICS.map((t, i) => {
            const isThis = i + 1 === order;
            return (
              <div
                key={t.id}
                title={`${t.name} (${t.id})`}
                className={[
                  "flex-1 rounded-[1px] transition-all",
                  isThis ? "h-4" : "h-1.5",
                  isThis
                    ? order >= 14
                      ? "bg-red-400"
                      : order >= 11
                        ? "bg-orange-400"
                        : order >= 6
                          ? "bg-yellow-400"
                          : "bg-sky-400"
                    : i + 1 < order
                      ? "bg-slate-600"
                      : "bg-slate-800",
                ].join(" ")}
              />
            );
          })}
        </div>
        <p className="text-[10px] text-slate-500">
          Stage {order} of {ATTACK_TACTICS.length} — {attack?.kill_chain_stage}
        </p>
      </div>

      {/* Corroborating techniques */}
      {others.length > 0 && (
        <div className="space-y-2 border-t border-slate-800 pt-3">
          <p className="eyebrow">Corroborating techniques</p>
          <ul className="space-y-1.5">
            {others.map((t) => (
              <li key={t.technique_id} className="flex items-baseline gap-2 text-[11px]">
                <a
                  href={t.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mono shrink-0 text-cyan-400 hover:underline"
                >
                  {t.technique_id}
                </a>
                <span className="text-slate-400">{t.technique_name}</span>
                <span className="ml-auto shrink-0 text-slate-600">{t.tactic_name}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

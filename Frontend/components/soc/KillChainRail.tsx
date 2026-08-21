"use client";

import { ATTACK_TACTICS, stageTone } from "@/lib/severity";

type ChainStep = {
  stage: string;
  order: number;
  first_seen?: string;
  technique?: string;
  technique_name?: string;
  event_id?: string;
};

/**
 * The whole ATT&CK lifecycle as a rail, with the stages this campaign actually
 * reached lit up.
 *
 * Showing only the reached stages would hide the thing that matters most — how
 * much further an intruder could still go. Rendering all 15 makes "reached
 * Exfiltration" land as the end of the line rather than as one label among many.
 */
export default function KillChainRail({
  chain,
  furthestOrder,
  compact = false,
}: {
  chain: ChainStep[];
  furthestOrder: number;
  compact?: boolean;
}) {
  const reached = new Set(chain.map((s) => s.order));

  return (
    <div className="space-y-2">
      <div className="flex items-end gap-[3px]">
        {ATTACK_TACTICS.map((tactic, i) => {
          const order = i + 1;
          const isReached = reached.has(order);
          const isBefore = order <= furthestOrder;

          return (
            <div key={tactic.id} className="group relative flex-1" title={`${tactic.name} (${tactic.id})`}>
              <div
                className={[
                  "w-full rounded-[1px] transition-all",
                  compact ? "h-1.5" : "h-2.5",
                  isReached
                    ? order >= 14
                      ? "bg-red-400"
                      : order >= 11
                        ? "bg-orange-400"
                        : order >= 6
                          ? "bg-yellow-400"
                          : "bg-sky-400"
                    : isBefore
                      ? "bg-slate-600"
                      : "bg-slate-800",
                ].join(" ")}
              />
              {!compact && (
                <span
                  className={[
                    "mt-1.5 block truncate text-center text-[8px] uppercase tracking-wide",
                    isReached ? "font-semibold text-slate-300" : "text-slate-600",
                  ].join(" ")}
                >
                  {tactic.short}
                </span>
              )}
            </div>
          );
        })}
      </div>

      {!compact && chain.length > 0 && (
        <p className="text-[10px] text-slate-500">
          Filled segments are stages this campaign reached. Grey segments up to the
          furthest point are lifecycle stages it skipped;{" "}
          <span className={stageTone(furthestOrder)}>
            it stopped at stage {furthestOrder} of {ATTACK_TACTICS.length}
          </span>
          .
        </p>
      )}
    </div>
  );
}

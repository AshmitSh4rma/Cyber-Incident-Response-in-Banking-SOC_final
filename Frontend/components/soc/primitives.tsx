"use client";

import type { ReactNode } from "react";
import {
  ATTACK_TACTICS,
  type Severity,
  clockTone,
  compact,
  formatRemaining,
  normalizeSeverity,
  severityTone,
  stageSeverity,
} from "@/lib/severity";

/* ─────────────────────────────────────────────────────────────────────────────
   SeverityChip

   The only sanctioned way to show severity. It always renders the word, so colour
   is never the sole channel — which matters because the severity scale is
   red/orange/yellow and those are not separable under colour-vision deficiency.
   ───────────────────────────────────────────────────────────────────────────── */

export function SeverityChip({
  value,
  size = "sm",
}: {
  value: unknown;
  size?: "xs" | "sm";
}) {
  const severity = normalizeSeverity(value);
  const tone = severityTone(severity);
  return (
    <span
      className={[
        "inline-flex items-center gap-1.5 rounded border font-semibold uppercase tracking-wider",
        size === "xs" ? "px-1.5 py-0.5 text-[9px]" : "px-2 py-0.5 text-[10px]",
        tone.chip,
      ].join(" ")}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${tone.mark}`} aria-hidden />
      {severity}
    </span>
  );
}

export function VerdictChip({ value }: { value: unknown }) {
  const label = String(value ?? "unknown");
  const tone =
    label.toLowerCase() === "malicious"
      ? "border-sev-critical/40 bg-sev-critical/15 text-sev-critical"
      : label.toLowerCase() === "suspicious"
        ? "border-sev-high/35 bg-sev-high/12 text-sev-high"
        : label.toLowerCase() === "suppressed"
          ? "border-rule bg-raised text-faint"
          : "border-sev-benign/35 bg-sev-benign/12 text-sev-benign";
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider ${tone}`}
    >
      {label}
    </span>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Stat tile

   Contract: label in sentence case, value in proportional figures (tabular
   figures make a display-size number look loose), optional supporting line.
   The value wears a TEXT token — identity comes from a mark beside it, never from
   colouring the number itself.
   ───────────────────────────────────────────────────────────────────────────── */

export function StatTile({
  label,
  value,
  unit,
  sub,
  mark,
}: {
  label: string;
  value: string | number;
  unit?: string;
  sub?: string;
  /** Optional colour mark carrying identity, e.g. a severity dot. */
  mark?: string;
}) {
  return (
    <div className="min-w-0 px-4 py-3.5">
      <p className="eyebrow truncate">{label}</p>
      <p className="mt-1.5 flex items-baseline gap-1.5">
        {mark ? <span className={`h-2 w-2 shrink-0 rounded-full ${mark}`} aria-hidden /> : null}
        <span className="figure text-[26px] font-semibold leading-none text-ink">
          {typeof value === "number" ? compact(value) : value}
        </span>
        {unit ? <span className="text-[11px] text-faint">{unit}</span> : null}
      </p>
      {sub ? <p className="mt-1.5 line-clamp-2 text-[11px] leading-snug text-muted">{sub}</p> : null}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Hero figure — the single number a view leads with. Exactly one per screen.
   ───────────────────────────────────────────────────────────────────────────── */

export function HeroFigure({
  value,
  unit,
  label,
  detail,
}: {
  value: string | number;
  unit?: string;
  label: string;
  detail?: ReactNode;
}) {
  return (
    <div className="min-w-0">
      <p className="eyebrow">{label}</p>
      <p className="mt-2 flex items-baseline gap-2">
        <span className="figure text-[56px] font-semibold leading-[0.9] text-ink">{value}</span>
        {unit ? <span className="text-sm font-medium text-muted">{unit}</span> : null}
      </p>
      {detail ? <div className="mt-2 text-xs leading-relaxed text-muted">{detail}</div> : null}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Severity distribution

   A single stacked bar. 2px surface gaps do the separating (no strokes), and each
   present severity is directly labelled, so the bar is readable without relying
   on the colour ramp.
   ───────────────────────────────────────────────────────────────────────────── */

export function SeverityBar({
  counts,
  total,
}: {
  counts: Partial<Record<Severity, number>>;
  total: number;
}) {
  const order: Severity[] = ["critical", "high", "medium", "low", "benign"];
  const present = order.filter((s) => (counts[s] ?? 0) > 0);

  if (total === 0 || present.length === 0) {
    return <p className="text-[11px] text-faint">No alerts in this window.</p>;
  }

  return (
    <div className="space-y-2.5">
      <div className="flex h-2.5 w-full gap-[2px] overflow-hidden rounded-sm">
        {present.map((s) => (
          <div
            key={s}
            className={severityTone(s).mark}
            style={{ width: `${((counts[s] ?? 0) / total) * 100}%` }}
            title={`${counts[s]} ${s}`}
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1.5">
        {present.map((s) => (
          <span key={s} className="flex items-center gap-1.5 text-[11px]">
            <span className={`h-2 w-2 rounded-full ${severityTone(s).mark}`} aria-hidden />
            <span className="tabular font-semibold text-ink">{counts[s]}</span>
            <span className="text-muted">{s}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Kill-chain meter

   All 15 ATT&CK tactics, with the stages a campaign actually reached filled in.
   Showing only the reached stages would hide the thing that matters most — how
   much further an intruder could still have gone.

   The unfilled track is a darker step of the fill's own hue rather than grey, so
   the state reads across the whole bar.
   ───────────────────────────────────────────────────────────────────────────── */

export function KillChainMeter({
  reachedOrders,
  furthestOrder,
  showLabels = false,
}: {
  reachedOrders: number[];
  furthestOrder: number;
  showLabels?: boolean;
}) {
  const reached = new Set(reachedOrders);
  const overall = severityTone(stageSeverity(furthestOrder));

  return (
    <div className="space-y-1.5">
      <div className="flex items-end gap-[2px]">
        {ATTACK_TACTICS.map((tactic, i) => {
          const order = i + 1;
          const isReached = reached.has(order);
          const isBefore = order <= furthestOrder;
          return (
            <div
              key={tactic.id}
              className="group/seg relative flex-1"
              title={`${tactic.name} (${tactic.id})${isReached ? " — reached" : ""}`}
            >
              <div
                className={[
                  "w-full rounded-[1px] transition-all",
                  showLabels ? "h-2.5" : "h-1.5",
                  isReached
                    ? severityTone(stageSeverity(order)).mark
                    : isBefore
                      ? overall.track
                      : "bg-track-neutral",
                ].join(" ")}
              />
              {showLabels ? (
                <span
                  className={[
                    "mt-1.5 block truncate text-center text-[8px] uppercase tracking-wide",
                    isReached ? "font-semibold text-muted" : "text-faint/50",
                  ].join(" ")}
                >
                  {tactic.short}
                </span>
              ) : null}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Notification clock

   The countdown to a regulatory notification deadline. Non-technical readers get
   this instantly, which is the point: it turns "severity high" into "you have
   3h 12m to tell the regulator".
   ───────────────────────────────────────────────────────────────────────────── */

export type Clock = {
  regime_id: string;
  authority: string;
  clock_label: string;
  instrument?: string;
  starts_from?: string;
  note?: string;
  url?: string;
  window_hours: number;
  deadline: string;
  seconds_remaining: number;
  state: string;
};

export function ClockRow({ clock, compactRow = false }: { clock: Clock; compactRow?: boolean }) {
  const tone = clockTone(clock.state);
  const elapsed = Math.min(
    100,
    Math.max(0, 100 - (clock.seconds_remaining / (clock.window_hours * 3600)) * 100),
  );

  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <span className="min-w-0 truncate text-[11px] font-medium text-ink">{clock.authority}</span>
        <span className="flex items-center gap-2">
          <span className="tabular text-[11px] font-semibold text-ink">
            {formatRemaining(clock.seconds_remaining)}
          </span>
          <span
            className={`rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider ${tone.chip}`}
          >
            {tone.label}
          </span>
        </span>
      </div>
      <div className="h-1 w-full overflow-hidden rounded-sm bg-track-neutral">
        <div className={`h-full ${tone.mark}`} style={{ width: `${elapsed}%` }} />
      </div>
      {!compactRow ? (
        <p className="text-[10px] text-faint">
          {clock.clock_label} from {clock.starts_from}
        </p>
      ) : null}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Section — a titled block. One shape for every panel in the app.
   ───────────────────────────────────────────────────────────────────────────── */

export function Section({
  title,
  hint,
  actions,
  children,
  className = "",
}: {
  title: string;
  hint?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`overflow-hidden rounded-md border border-rule bg-surface ${className}`}>
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-rule-soft px-4 py-2.5">
        <div className="min-w-0">
          <h2 className="eyebrow truncate">{title}</h2>
          {hint ? <p className="mt-0.5 text-[10px] text-faint">{hint}</p> : null}
        </div>
        {actions}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

/**
 * Plain-language explainer.
 *
 * Every technical panel gets one. A judge or an executive should be able to read
 * a screen without knowing what a CVSS vector is, and an analyst should be able
 * to skip it entirely — so it is one sentence, visually quiet, never a modal.
 */
export function PlainEnglish({ children }: { children: ReactNode }) {
  return (
    <p className="border-l-2 border-accent-deep pl-3 text-[11px] leading-relaxed text-muted">
      {children}
    </p>
  );
}

export function EmptyState({
  title,
  detail,
  icon,
}: {
  title: string;
  detail: string;
  icon?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-md border border-dashed border-rule bg-sunk/40 px-6 py-14 text-center">
      {icon ? <div className="mb-3 text-faint">{icon}</div> : null}
      <p className="text-sm font-medium text-ink">{title}</p>
      <p className="mt-1.5 max-w-sm text-xs leading-relaxed text-muted">{detail}</p>
    </div>
  );
}

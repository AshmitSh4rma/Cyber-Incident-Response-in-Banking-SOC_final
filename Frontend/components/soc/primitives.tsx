"use client";

import { useState, type ReactNode } from "react";
import Link from "next/link";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown } from "lucide-react";

import { useDetail } from "@/lib/detail";
import {
  EASE_OUT,
  expand,
  useCountUpInt,
  useLiveCountdown,
  usePrefersReducedMotion,
} from "@/lib/motion";
import {
  ATTACK_TACTICS,
  type Severity,
  clockTone,
  compact,
  normalizeSeverity,
  severityTone,
  stageSeverity,
  verdictTone,
} from "@/lib/severity";

/* ─────────────────────────────────────────────────────────────────────────────
   Layout: Screen / Section

   One shape for every panel. `Screen` staggers its children so a page assembles
   rather than appearing all at once.

   The entrance is a CSS class, not a JavaScript animation. Driving it from the
   animation library meant every panel's resting state was `opacity: 0` with the
   library responsible for clearing it, so anything that stopped it running left
   the page blank rather than unanimated. `.rise` animates *from* hidden toward
   the element's own visible styles, which means a page that never animates is a
   page that simply appears. `.screen` staggers its direct children.
   ───────────────────────────────────────────────────────────────────────────── */

export function Screen({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`screen mx-auto max-w-[1420px] space-y-4 ${className}`}>{children}</div>
  );
}

export function Block({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`rise ${className}`}>{children}</div>;
}

export function Section({
  title,
  hint,
  actions,
  children,
  className = "",
  flush = false,
}: {
  title: string;
  hint?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  flush?: boolean;
}) {
  return (
    <section
      className={`rise overflow-hidden rounded-lg border border-rule bg-surface ${className}`}
    >
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-rule-soft px-4 py-3">
        <div className="min-w-0">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted">{title}</h2>
          {hint ? <p className="mt-0.5 text-[10px] text-faint">{hint}</p> : null}
        </div>
        {actions}
      </header>
      <div className={flush ? "" : "p-4"}>{children}</div>
    </section>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Reveal — the progressive-disclosure primitive.

   Everything technical lives inside one of these. Collapsed by default, labelled
   in words rather than behind an icon, and the height animates so it is obvious
   the content came from the thing you clicked.
   ───────────────────────────────────────────────────────────────────────────── */

export function Reveal({
  label,
  children,
  defaultOpen = false,
  count,
}: {
  label: string;
  children: ReactNode;
  defaultOpen?: boolean;
  count?: number;
}) {
  const { isAnalyst } = useDetail();
  const [open, setOpen] = useState(defaultOpen || isAnalyst);

  return (
    <div className="overflow-hidden rounded border border-rule-soft bg-sunk/40">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 px-3 py-2 text-left transition hover:bg-raised/50"
      >
        <motion.span
          animate={{ rotate: open ? 0 : -90 }}
          transition={{ duration: 0.2, ease: EASE_OUT }}
          className="shrink-0 text-faint"
        >
          <ChevronDown className="h-3 w-3" />
        </motion.span>
        <span className="text-[11px] font-medium text-muted">{label}</span>
        {count !== undefined ? (
          <span className="tabular text-[10px] text-faint">{count}</span>
        ) : null}
      </button>

      <AnimatePresence initial={false}>
        {open ? (
          <motion.div variants={expand} initial="collapsed" animate="open" exit="collapsed">
            <div className="border-t border-rule-soft px-3 py-3">{children}</div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Status chips. Severity always renders its word — the ramp is red/orange/yellow
   and those are not separable under colour-vision deficiency, so colour is never
   the only channel.
   ───────────────────────────────────────────────────────────────────────────── */

export function SeverityChip({ value, size = "sm" }: { value: unknown; size?: "xs" | "sm" }) {
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
  const label = String(value ?? "unknown").toLowerCase();
  const tone = verdictTone(label);
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider ${tone}`}
    >
      {label}
    </span>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Figures
   ───────────────────────────────────────────────────────────────────────────── */

/** The single number a screen leads with. Exactly one per view. */
export function HeroFigure({
  value,
  unit,
  label,
  detail,
}: {
  value: number;
  unit?: string;
  label: string;
  detail?: ReactNode;
}) {
  const shown = useCountUpInt(value, 850);
  return (
    <div className="min-w-0">
      <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className="mt-2.5 flex items-baseline gap-2.5">
        <span className="figure text-[62px] font-semibold leading-[0.88] text-ink">{shown}</span>
        {unit ? <span className="text-sm font-medium text-muted">{unit}</span> : null}
      </p>
      {detail ? <div className="mt-3 text-[13px] leading-relaxed text-muted">{detail}</div> : null}
    </div>
  );
}

export function StatTile({
  label,
  value,
  unit,
  sub,
  animate = true,
}: {
  label: string;
  value: string | number;
  unit?: string;
  sub?: string;
  animate?: boolean;
}) {
  const numeric = typeof value === "number";
  const counted = useCountUpInt(numeric ? value : 0, 700);
  const display = numeric ? (animate ? compact(counted) : compact(value)) : value;

  return (
    <div className="min-w-0 px-4 py-3.5">
      <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-faint">{label}</p>
      <p className="mt-1.5 flex items-baseline gap-1.5">
        <span className="figure text-[24px] font-semibold leading-none text-ink">{display}</span>
        {unit ? <span className="text-[11px] text-faint">{unit}</span> : null}
      </p>
      {sub ? <p className="mt-1.5 line-clamp-2 text-[11px] leading-snug text-muted">{sub}</p> : null}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Severity distribution — one stacked bar, 2px gaps doing the separating, every
   present band directly labelled.
   ───────────────────────────────────────────────────────────────────────────── */

export function SeverityBar({
  counts,
  total,
  linkTo,
}: {
  counts: Partial<Record<Severity, number>>;
  total: number;
  /**
   * Makes each band a link to that severity on its own. Optional because the
   * bar is also used where there is nowhere to drill into — the point of the
   * distribution on the overview is to be the way *into* the work, and a count
   * you can read but not follow makes the reader go find the filter themselves.
   */
  linkTo?: (severity: Severity) => string;
}) {
  const reduced = usePrefersReducedMotion();
  const order: Severity[] = ["critical", "high", "medium", "low", "benign"];
  const present = order.filter((s) => (counts[s] ?? 0) > 0);

  if (total === 0 || present.length === 0) {
    return <p className="text-[11px] text-faint">Nothing needs attention right now.</p>;
  }

  return (
    <div className="space-y-3">
      <div className="flex h-2.5 w-full gap-[2px] overflow-hidden rounded-sm">
        {present.map((s, i) => (
          <motion.div
            key={s}
            className={severityTone(s).mark}
            initial={reduced ? false : { width: 0 }}
            animate={{ width: `${((counts[s] ?? 0) / total) * 100}%` }}
            transition={{ duration: 0.6, delay: 0.1 + i * 0.07, ease: EASE_OUT }}
            title={`${counts[s]} ${s}`}
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1.5">
        {present.map((s) => {
          const body = (
            <>
              <span className={`h-2 w-2 rounded-full ${severityTone(s).mark}`} aria-hidden />
              <span className="tabular font-semibold text-ink">{counts[s]}</span>
              <span className="text-muted">{s}</span>
            </>
          );
          return linkTo ? (
            <Link
              key={s}
              href={linkTo(s)}
              className="flex items-center gap-1.5 rounded text-[11px] transition hover:opacity-80"
              title={`Open the ${s} alerts`}
            >
              {body}
            </Link>
          ) : (
            <span key={s} className="flex items-center gap-1.5 text-[11px]">
              {body}
            </span>
          );
        })}
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Kill-chain meter — all 15 tactics, the reached ones filled, segments arriving
   left to right so the sequence reads as a sequence.
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
  const reduced = usePrefersReducedMotion();
  const reached = new Set(reachedOrders);
  const overall = severityTone(stageSeverity(furthestOrder));

  return (
    <div className="flex items-end gap-[2px]">
      {ATTACK_TACTICS.map((tactic, i) => {
        const order = i + 1;
        const isReached = reached.has(order);
        const isBefore = order <= furthestOrder;
        return (
          <div
            key={tactic.id}
            className="min-w-0 flex-1"
            title={`${tactic.name}${isReached ? " — reached" : ""}`}
          >
            <motion.div
              initial={reduced ? false : { scaleY: 0.2, opacity: 0 }}
              animate={{ scaleY: 1, opacity: 1 }}
              transition={{ duration: 0.32, delay: 0.12 + i * 0.028, ease: EASE_OUT }}
              style={{ originY: 1 }}
              className={[
                "w-full rounded-[1px]",
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
                  isReached ? "font-semibold text-muted" : "text-faint/40",
                ].join(" ")}
              >
                {tactic.short}
              </span>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Notification clock — a countdown that actually ticks.
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

export function ClockRow({ clock, prominent = false }: { clock: Clock; prominent?: boolean }) {
  const live = useLiveCountdown(clock.deadline, clock.window_hours);
  const tone = clockTone(live.state);
  const reduced = usePrefersReducedMotion();

  /**
   * The dial reads from `live`, not from the `seconds_remaining` the server sent.
   * That field is a snapshot from the moment of the response, so a dial driven by
   * it is frozen at page load while looking like it is counting — the one failure
   * mode a notification deadline cannot have.
   */
  const radius = 9;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - live.elapsed * circumference;

  // Derived from the same three states the backend actually emits — overdue,
  // due_soon, on_track. An unreachable fourth state here would silently paint a
  // deadline about to be missed in the on-track colour.
  const dialStroke =
    live.state === "overdue"
      ? "stroke-sev-critical"
      : live.state === "due_soon"
        ? "stroke-sev-high"
        : "stroke-sev-benign";

  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-rule-soft/60 bg-raised/40 p-3 transition hover:border-rule">
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={[
              "min-w-0 truncate font-semibold text-ink",
              prominent ? "text-[13px]" : "text-xs",
            ].join(" ")}
          >
            {clock.authority}
          </span>
          <span
            className={`inline-flex shrink-0 items-center gap-1 rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider ${tone.chip}`}
          >
            {live.state !== "on_track" && !reduced ? (
              <span className={`h-1 w-1 rounded-full ${tone.mark} pulse-dot`} aria-hidden />
            ) : null}
            {tone.label}
          </span>
        </div>

        <p className="flex flex-wrap items-baseline gap-1.5 text-[10px] text-faint">
          <span className="truncate">{clock.clock_label}</span>
          <span aria-hidden>·</span>
          <span
            className={[
              "tabular font-semibold",
              prominent ? "text-[13px]" : "text-[11px]",
              live.state === "overdue" ? "text-sev-critical" : "text-ink",
            ].join(" ")}
          >
            {live.label}
          </span>
        </p>

        {prominent && clock.starts_from ? (
          <p className="truncate text-[10px] text-faint">from {clock.starts_from}</p>
        ) : null}
      </div>

      <div
        className="relative flex h-7 w-7 shrink-0 items-center justify-center"
        title={`${Math.round(live.elapsed * 100)}% of the window elapsed · ${live.label}`}
      >
        <svg className="h-7 w-7 -rotate-90" viewBox="0 0 24 24" aria-hidden>
          <circle
            cx="12"
            cy="12"
            r={radius}
            className="stroke-track-neutral"
            strokeWidth="2.5"
            fill="transparent"
          />
          <motion.circle
            cx="12"
            cy="12"
            r={radius}
            className={dialStroke}
            strokeWidth="2.5"
            strokeDasharray={circumference}
            strokeLinecap="round"
            fill="transparent"
            initial={reduced ? false : { strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 0.9, ease: EASE_OUT }}
          />
        </svg>
        <span className="absolute h-1.5 w-1.5 rounded-full bg-ink/80" aria-hidden />
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Prose helpers
   ───────────────────────────────────────────────────────────────────────────── */

/**
 * The plain-language line. Every screen has one near the top; a reader who knows
 * nothing about security should be able to follow the page from these alone.
 */
export function PlainEnglish({ children }: { children: ReactNode }) {
  return (
    <p className="border-l-2 border-accent-deep pl-3 text-[12px] leading-relaxed text-muted">
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
    <div className="fade flex flex-col items-center justify-center rounded-lg border border-dashed border-rule bg-sunk/40 px-6 py-14 text-center">
      {icon ? <div className="mb-3 text-faint">{icon}</div> : null}
      <p className="text-sm font-medium text-ink">{title}</p>
      <p className="mt-1.5 max-w-sm text-xs leading-relaxed text-muted">{detail}</p>
    </div>
  );
}

export function Skeleton({ className = "h-24" }: { className?: string }) {
  return <div className={`animate-pulse rounded-lg bg-raised ${className}`} />;
}

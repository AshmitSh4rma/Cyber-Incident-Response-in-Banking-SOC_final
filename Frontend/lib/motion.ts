"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { Transition, Variants } from "framer-motion";

/**
 * Shared motion vocabulary.
 *
 * One set of curves and durations for the whole console, so movement reads as one
 * system rather than each screen having its own idea of how fast things are.
 *
 * The rules this follows:
 *  - Motion carries meaning or it does not ship. Entrances orient you, the
 *    countdown conveys urgency, an expander shows where content came from.
 *    Nothing moves decoratively.
 *  - Short and small. 200-420ms, 4-10px of travel. A security console is read,
 *    not admired; anything slower gets in the way by the fifth visit.
 *  - Everything here is disabled under `prefers-reduced-motion`, and the
 *    animated-number hooks jump straight to their final value rather than
 *    freezing mid-count.
 */

export const EASE_OUT = [0.16, 1, 0.3, 1] as const;
export const EASE_IN_OUT = [0.65, 0, 0.35, 1] as const;

export const SPRING: Transition = { type: "spring", stiffness: 420, damping: 34, mass: 0.7 };

/** Does the viewer want motion suppressed? */
export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(mq.matches);
    const onChange = (e: MediaQueryListEvent) => setReduced(e.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  return reduced;
}

/* ─── Entrance variants ────────────────────────────────────────────────────── */

/** Parent: staggers its children so a screen assembles top-down. */
export const stagger = (delayChildren = 0.04, staggerChildren = 0.045): Variants => ({
  hidden: {},
  shown: { transition: { delayChildren, staggerChildren } },
});

/** Child: rises a few pixels into place. */
export const riseIn: Variants = {
  hidden: { opacity: 0, y: 8 },
  shown: { opacity: 1, y: 0, transition: { duration: 0.38, ease: EASE_OUT } },
};

/** Child: fades only. For dense rows where vertical travel would look busy. */
export const fadeIn: Variants = {
  hidden: { opacity: 0 },
  shown: { opacity: 1, transition: { duration: 0.3, ease: EASE_OUT } },
};

/** A panel expanding open. Height animation, so the page reflows smoothly. */
export const expand: Variants = {
  collapsed: { height: 0, opacity: 0 },
  open: {
    height: "auto",
    opacity: 1,
    transition: { height: { duration: 0.3, ease: EASE_OUT }, opacity: { duration: 0.22, delay: 0.06 } },
  },
};

/* ─── Animated numbers ─────────────────────────────────────────────────────── */

/**
 * Count a number up to its target once, on mount.
 *
 * Deliberately not a spring: a metric that overshoots and settles reads as
 * unreliable, and on a dashboard where the number *is* the claim that matters.
 * Eases out to the exact target and stops.
 */
export function useCountUp(target: number, durationMs = 900): number {
  const reduced = usePrefersReducedMotion();
  const [value, setValue] = useState(reduced ? target : 0);
  const frame = useRef<number>(0);

  useEffect(() => {
    if (reduced || !Number.isFinite(target)) {
      setValue(target);
      return;
    }

    const start = performance.now();
    const from = 0;

    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs);
      // easeOutCubic — fast start, clean stop, no overshoot.
      const eased = 1 - Math.pow(1 - t, 3);
      setValue(from + (target - from) * eased);
      if (t < 1) frame.current = requestAnimationFrame(tick);
      else setValue(target);
    };

    frame.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame.current);
  }, [target, durationMs, reduced]);

  return value;
}

/** Integer form, for counts. */
export function useCountUpInt(target: number, durationMs = 900): number {
  return Math.round(useCountUp(target, durationMs));
}

/* ─── Live countdown ──────────────────────────────────────────────────────── */

export type Countdown = {
  secondsRemaining: number;
  label: string;
  /** 0-1, how much of the window has elapsed. */
  elapsed: number;
  state: "on_track" | "due_soon" | "overdue";
};

/**
 * A regulatory deadline that actually ticks.
 *
 * The server sends an absolute deadline and a window; this recomputes locally
 * every second. That matters beyond polish — a countdown frozen at the value it
 * had when the page loaded is worse than no countdown, because it looks live and
 * is not. Recomputing from the absolute deadline also means it stays correct
 * across a laptop sleeping or a tab sitting in the background.
 */
export function useLiveCountdown(deadlineIso: string, windowHours: number): Countdown {
  const deadline = useMemo(() => new Date(deadlineIso).getTime(), [deadlineIso]);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const secondsRemaining = Math.round((deadline - now) / 1000);
  const windowSeconds = Math.max(1, windowHours * 3600);
  const elapsed = Math.min(1, Math.max(0, 1 - secondsRemaining / windowSeconds));

  const state: Countdown["state"] =
    secondsRemaining <= 0 ? "overdue" : secondsRemaining <= windowSeconds * 0.25 ? "due_soon" : "on_track";

  return { secondsRemaining, label: formatRemaining(secondsRemaining), elapsed, state };
}

/** 'in 3h 12m 04s' at the sharp end, coarser when there is time to spare. */
export function formatRemaining(seconds: number): string {
  const overdue = seconds < 0;
  const s = Math.abs(Math.round(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;

  let text: string;
  if (h >= 24) text = `${Math.floor(h / 24)}d ${h % 24}h`;
  else if (h >= 1) text = `${h}h ${String(m).padStart(2, "0")}m`;
  // Under an hour, show seconds — that is when a person starts watching it.
  else text = `${m}m ${String(sec).padStart(2, "0")}s`;

  return overdue ? `overdue by ${text}` : text;
}

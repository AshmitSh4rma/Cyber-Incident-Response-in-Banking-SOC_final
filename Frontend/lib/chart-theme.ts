"use client";

import { useSyncExternalStore } from "react";

/**
 * Chart colours, read from the design tokens at runtime.
 *
 * Recharts styles its SVG through props — `fill`, `stroke`, `contentStyle` —
 * which take colour *values*, not class names, so a chart cannot reach the
 * palette the way the rest of the console does. The alternative is writing hex
 * literals into the chart component, and then the charts quietly keep the old
 * colours the next time the theme changes. So the tokens stay the single source
 * of truth and this reads them off the document.
 *
 * Modelled on lib/detail.tsx: the computed stylesheet is an external system, so
 * it is subscribed to rather than copied into state inside an effect. The
 * snapshot is cached because useSyncExternalStore compares by reference — a
 * fresh object each call would re-render forever.
 *
 * The server fallback matters: there is no computed style during the server
 * render, and a chart handed `undefined` colours draws nothing at all.
 */

export type ChartTheme = {
  /** Categorical series colours, in order. */
  series: string[];
  /** Axis tick labels. */
  axis: string;
  /** Axis lines and grid. */
  grid: string;
  /** Tooltip panel. */
  tooltipBg: string;
  tooltipBorder: string;
  tooltipText: string;
  /** The hover band behind a bar. */
  cursor: string;
};

const FALLBACK: ChartTheme = {
  series: ["#00e5ff", "#00b8d4", "#4d8cff", "#a77bff", "#00d68f"],
  axis: "#56916a",
  grid: "#17401f",
  tooltipBg: "#071008",
  tooltipBorder: "#17401f",
  tooltipText: "#d6f5dd",
  cursor: "rgba(0, 232, 90, 0.06)",
};

function read(styles: CSSStyleDeclaration, name: string, fallback: string): string {
  const value = styles.getPropertyValue(name).trim();
  return value || fallback;
}

let cached: ChartTheme | null = null;

function getSnapshot(): ChartTheme {
  if (cached) return cached;
  const styles = getComputedStyle(document.documentElement);
  cached = {
    series: [1, 2, 3, 4, 5].map((n) => read(styles, `--chart-${n}`, FALLBACK.series[n - 1])),
    axis: read(styles, "--faint", FALLBACK.axis),
    grid: read(styles, "--rule", FALLBACK.grid),
    tooltipBg: read(styles, "--surface", FALLBACK.tooltipBg),
    tooltipBorder: read(styles, "--rule", FALLBACK.tooltipBorder),
    tooltipText: read(styles, "--text", FALLBACK.tooltipText),
    cursor: FALLBACK.cursor,
  };
  return cached;
}

function getServerSnapshot(): ChartTheme {
  return FALLBACK;
}

/** The tokens do not change after load, so there is nothing to notify about. */
function subscribe(): () => void {
  return () => {};
}

export function useChartTheme(): ChartTheme {
  return useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}

/** Cycles, so a chart with more categories than colours still draws them all. */
export function seriesColor(theme: ChartTheme, index: number): string {
  return theme.series[index % theme.series.length];
}

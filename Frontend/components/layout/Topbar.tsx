"use client";

import { usePathname } from "next/navigation";
import { motion } from "framer-motion";

import { useDetail } from "@/lib/detail";
import { EASE_OUT } from "@/lib/motion";

const TITLES: [RegExp, string][] = [
  [/^\/dashboard/, "Overview"],
  [/^\/campaigns\/[^/]+/, "Attack chain"],
  [/^\/campaigns/, "Attack chains"],
  [/^\/compliance/, "Reporting deadlines"],
  [/^\/incident\//, "Investigation"],
  [/^\/upload/, "Simulation"],
];

/**
 * Context bar. Carries where you are and the one control that changes how much
 * the console shows you.
 */
export default function Topbar() {
  const pathname = usePathname() ?? "";
  const title = TITLES.find(([re]) => re.test(pathname))?.[1] ?? "SENTRA";
  const { level, setLevel } = useDetail();

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between gap-4 border-b border-rule bg-ground/90 px-4 py-2.5 backdrop-blur-md md:px-6">
      <div className="flex min-w-0 items-center gap-2.5">
        <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-sev-benign pulse-dot" aria-hidden />
        <h1 className="truncate text-[11px] font-semibold uppercase tracking-[0.18em] text-muted">
          {title}
        </h1>
      </div>

      {/* Detail level. Labelled in words: an icon-only toggle here would hide the
          single most useful control in the product. */}
      <div
        className="relative flex shrink-0 items-center rounded-md border border-rule bg-sunk p-0.5"
        role="group"
        aria-label="Detail level"
      >
        {(["overview", "analyst"] as const).map((option) => {
          const active = level === option;
          return (
            <button
              key={option}
              onClick={() => setLevel(option)}
              aria-pressed={active}
              className="relative px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider transition-colors"
            >
              {active ? (
                <motion.span
                  layoutId="detail-pill"
                  transition={{ duration: 0.24, ease: EASE_OUT }}
                  className="absolute inset-0 rounded bg-raised"
                />
              ) : null}
              <span className={`relative ${active ? "text-ink" : "text-faint hover:text-muted"}`}>
                {option === "overview" ? "Simple" : "Detailed"}
              </span>
            </button>
          );
        })}
      </div>
    </header>
  );
}

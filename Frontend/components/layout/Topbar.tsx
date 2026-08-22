"use client";

import { usePathname } from "next/navigation";
import { motion } from "framer-motion";

import { useDetail } from "@/lib/detail";
import { EASE_OUT } from "@/lib/motion";

const TITLES: [RegExp, string][] = [
  [/^\/dashboard/, "Overview"],
  [/^\/queue/, "Triage queue"],
  [/^\/campaigns\/[^/]+/, "Attack chain"],
  [/^\/campaigns/, "Attack chains"],
  [/^\/compliance/, "Reporting deadlines"],
  [/^\/incident\//, "Investigation"],
  [/^\/ai/, "Ask SENTRA"],
  [/^\/upload/, "Simulation"],
  [/^\/statistics/, "Statistics"],
  [/^\/settings/, "Settings"],
];

/**
 * Context bar. Carries the product mark, where you are, and the one control
 * that changes how much the console shows you.
 *
 * The mark lives here rather than in the navigation rail because the rail is
 * icon-only and 80px wide, with no room for a wordmark.
 *
 * There is deliberately no account avatar. This console has no sign-in, so a
 * face in the corner would imply an identity and a session that do not exist.
 */
export default function Topbar() {
  const pathname = usePathname() ?? "";
  const title = TITLES.find(([re]) => re.test(pathname))?.[1] ?? "SENTRA";
  const { level, setLevel } = useDetail();

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between gap-4 border-b border-rule bg-ground/90 px-4 py-2.5 backdrop-blur-md md:px-6">
      <div className="flex min-w-0 items-center gap-3">
        <span
          className="flex h-6 w-6 shrink-0 items-center justify-center rounded border border-accent/25 bg-accent/10"
          aria-hidden
        >
          <svg viewBox="0 0 24 24" className="h-3.5 w-3.5 text-accent" fill="none">
            <path
              d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7l-9-5z"
              fill="currentColor"
              opacity="0.85"
            />
          </svg>
        </span>
        <span className="shrink-0 text-sm font-semibold tracking-tight text-ink">SENTRA</span>
        <span className="shrink-0 text-faint" aria-hidden>
          /
        </span>
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

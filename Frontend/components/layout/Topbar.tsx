"use client";

import { usePathname } from "next/navigation";

const TITLES: [RegExp, string][] = [
  [/^\/dashboard/, "Incident queue"],
  [/^\/campaigns\/[^/]+/, "Campaign"],
  [/^\/campaigns/, "Campaigns"],
  [/^\/compliance/, "Regulatory notification"],
  [/^\/incident\//, "Investigation"],
  [/^\/upload/, "Attack simulation"],
];

export default function Topbar() {
  const pathname = usePathname() ?? "";
  const title = TITLES.find(([re]) => re.test(pathname))?.[1] ?? "SENTRA";

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between gap-4 border-b border-rule bg-ground/95 px-4 py-3 backdrop-blur md:px-6">
      <div className="flex min-w-0 items-center gap-2.5">
        <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-sev-benign pulse-dot" aria-hidden />
        <h1 className="truncate text-xs font-semibold uppercase tracking-[0.18em] text-muted">
          {title}
        </h1>
      </div>
      <p className="hidden text-[10px] text-faint sm:block">
        Banking SOC · automated triage and response
      </p>
    </header>
  );
}

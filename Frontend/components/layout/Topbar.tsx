"use client";

import { usePathname } from "next/navigation";
import { User } from "lucide-react";

const TITLES: [RegExp, string][] = [
  [/^\/dashboard/, "Dashboard"],
  [/^\/queue/, "Triage Queue"],
  [/^\/campaigns\/[^/]+/, "Campaign"],
  [/^\/campaigns/, "Campaigns"],
  [/^\/compliance/, "Regulatory notification"],
  [/^\/incident\//, "Investigation"],
  [/^\/ai/, "Agentic AI"],
  [/^\/upload/, "Attack simulation"],
];

export default function Topbar() {
  const pathname = usePathname() ?? "";
  const title = TITLES.find(([re]) => re.test(pathname))?.[1] ?? "SENTRA";

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between gap-4 border-b border-rule bg-ground/95 px-5 py-2.5 backdrop-blur">
      <div className="flex min-w-0 items-center gap-3">
        <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded bg-accent/10 border border-accent/20">
          <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none">
            <path
              d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7l-9-5z"
              fill="currentColor"
              className="text-accent"
              opacity="0.85"
            />
          </svg>
        </div>
        <span className="text-sm font-semibold tracking-tight text-ink">
          SENTRA
        </span>
        <span className="text-faint">/</span>
        <h1 className="truncate text-xs font-medium text-muted">
          {title}
        </h1>
      </div>

      <div className="flex items-center gap-1">
        <div className="ml-2 flex h-7 w-7 items-center justify-center rounded-full bg-accent/15 text-accent">
          <User className="h-3.5 w-3.5" />
        </div>
      </div>
    </header>
  );
}

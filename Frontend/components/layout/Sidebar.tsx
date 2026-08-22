"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion } from "framer-motion";
import { GitBranch, Landmark, LayoutDashboard, ShieldCheck, SlidersHorizontal, UploadCloud } from "lucide-react";

import { EASE_OUT } from "@/lib/motion";

/**
 * Primary navigation.
 *
 * Four destinations, named for what you go there to do rather than for the layer
 * of the pipeline that produces them.
 *
 * The footer used to show three always-green rows — "Threat Pipeline", "ML
 * Detection Engine", "MITRE Framework". They were hardcoded, so they were
 * decoration rather than status, and one of them advertised machine learning this
 * system does not use: detection is rule-based, which the README says plainly.
 * It now reports one thing it can actually determine — whether the analysis
 * service is answering.
 */

const NAV = [
  {
    href: "/dashboard",
    label: "Overview",
    sublabel: "What needs attention",
    icon: LayoutDashboard,
  },
  {
    href: "/campaigns",
    label: "Attacks",
    sublabel: "Alerts that are one attack",
    icon: GitBranch,
  },
  {
    href: "/compliance",
    label: "Reporting",
    sublabel: "Regulator deadlines",
    icon: Landmark,
  },
  {
    href: "/upload",
    label: "Simulation",
    sublabel: "Replay an attack",
    icon: UploadCloud,
  },
  {
    href: "/settings",
    label: "Settings",
    sublabel: "Thresholds and policy",
    icon: SlidersHorizontal,
  },
];

export default function Sidebar() {
  const pathname = usePathname() ?? "";

  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r border-rule bg-sunk md:flex">
      {/* Mark */}
      <div className="flex items-center gap-3 border-b border-rule px-5 py-4">
        <div className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-accent-deep/40 bg-accent/10">
          <ShieldCheck className="h-4 w-4 text-accent" />
        </div>
        <div className="min-w-0">
          <p className="text-[13px] font-semibold leading-none tracking-tight text-ink">SENTRA</p>
          <p className="mt-1 text-[9px] uppercase tracking-[0.18em] text-faint">Banking SOC</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 p-3">
        {NAV.map((item) => {
          const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className="relative flex items-center gap-3 rounded-md px-3 py-2.5 transition"
            >
              {active ? (
                <motion.span
                  layoutId="nav-active"
                  transition={{ duration: 0.26, ease: EASE_OUT }}
                  className="absolute inset-0 rounded-md border border-rule bg-raised"
                />
              ) : null}
              <Icon
                className={`relative h-4 w-4 shrink-0 transition-colors ${
                  active ? "text-accent" : "text-faint group-hover:text-muted"
                }`}
              />
              <span className="relative min-w-0">
                <span
                  className={`block truncate text-[12px] font-medium leading-tight transition-colors ${
                    active ? "text-ink" : "text-muted"
                  }`}
                >
                  {item.label}
                </span>
                <span className="mt-0.5 block truncate text-[10px] text-faint">{item.sublabel}</span>
              </span>
            </Link>
          );
        })}
      </nav>

      <ServiceStatus />
    </aside>
  );
}

/**
 * One honest status line: is the analysis service answering?
 *
 * Polled, not asserted. If the backend is down this says so, which is the whole
 * point — an indicator that is green whatever happens is worse than none.
 */
function ServiceStatus() {
  const [state, setState] = useState<"checking" | "up" | "down">("checking");

  useEffect(() => {
    let alive = true;
    const check = async () => {
      try {
        const res = await fetch("/api/metrics", { cache: "no-store" });
        if (alive) setState(res.ok ? "up" : "down");
      } catch {
        if (alive) setState("down");
      }
    };
    check();
    const id = window.setInterval(check, 15_000);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
  }, []);

  const tone =
    state === "up"
      ? { dot: "bg-sev-benign", text: "text-sev-benign", label: "Connected" }
      : state === "down"
        ? { dot: "bg-sev-critical", text: "text-sev-critical", label: "Not reachable" }
        : { dot: "bg-faint", text: "text-faint", label: "Checking" };

  return (
    <div className="border-t border-rule p-3">
      <div className="flex items-center justify-between rounded-md border border-rule bg-surface px-3 py-2.5">
        <span className="text-[10px] uppercase tracking-[0.14em] text-faint">Analysis service</span>
        <span className="flex items-center gap-1.5">
          <span
            className={`h-1.5 w-1.5 rounded-full ${tone.dot} ${state === "checking" ? "pulse-dot" : ""}`}
            aria-hidden
          />
          <span className={`text-[10px] font-semibold ${tone.text}`}>{tone.label}</span>
        </span>
      </div>
    </div>
  );
}

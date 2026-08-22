"use client";

import { useEffect, useState } from "react";
import {
  BarChart3,
  Bot,
  Crosshair,
  GitBranch,
  Landmark,
  LayoutDashboard,
  ListTodo,
  SlidersHorizontal,
} from "lucide-react";

import Dock from "./Dock";

/**
 * Primary navigation: a vertical dock of destinations.
 *
 * Icon-only, with the name appearing on hover or focus. Every destination the
 * console has is here — dropping one from the rail is the same as removing the
 * feature, since there is no other way to reach it.
 *
 * The footer reports one thing it can actually determine: whether the analysis
 * service is answering. An earlier revision of this rail had a permanently green
 * pulsing dot next to a version number, which is decoration wearing the costume
 * of status. A dot that is green whatever happens is worse than no dot.
 */

const NAV = [
  { href: "/dashboard", label: "Overview", icon: <LayoutDashboard size={20} strokeWidth={2} /> },
  { href: "/queue", label: "Triage queue", icon: <ListTodo size={20} strokeWidth={2} /> },
  { href: "/campaigns", label: "Attacks", icon: <GitBranch size={20} strokeWidth={2} /> },
  { href: "/compliance", label: "Reporting", icon: <Landmark size={20} strokeWidth={2} /> },
  { href: "/ai", label: "Ask SENTRA", icon: <Bot size={20} strokeWidth={2} /> },
  { href: "/upload", label: "Simulation", icon: <Crosshair size={20} strokeWidth={2} /> },
  { href: "/statistics", label: "Statistics", icon: <BarChart3 size={20} strokeWidth={2} /> },
  { href: "/settings", label: "Settings", icon: <SlidersHorizontal size={20} strokeWidth={2} /> },
];

export default function Sidebar() {
  return (
    <aside className="relative z-50 hidden w-[80px] shrink-0 flex-col md:flex">
      <Dock items={NAV} />
      <ServiceStatus />
    </aside>
  );
}

/**
 * One honest status line: is the analysis service answering?
 *
 * Polled, not asserted. If the backend is down this says so, which is the whole
 * point. The rail is too narrow for a sentence, so the words live in the title
 * and the colour carries it at a glance — but the colour is derived from a real
 * request, never hardcoded.
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
      ? { dot: "bg-sev-benign", text: "text-sev-benign", label: "Connected", short: "LIVE" }
      : state === "down"
        ? { dot: "bg-sev-critical", text: "text-sev-critical", label: "Not reachable", short: "DOWN" }
        : { dot: "bg-faint", text: "text-faint", label: "Checking", short: "···" };

  return (
    <div
      className="absolute bottom-4 left-0 right-0 z-40 flex flex-col items-center gap-1.5 py-4"
      title={`Analysis service: ${tone.label}`}
    >
      <span
        className={`h-2 w-2 rounded-full ${tone.dot} ${state === "checking" ? "pulse-dot" : ""}`}
        aria-hidden
      />
      <span className={`text-[8px] font-semibold uppercase tracking-[0.12em] ${tone.text}`}>
        {tone.short}
      </span>
      <span className="sr-only" role="status">
        Analysis service: {tone.label}
      </span>
    </div>
  );
}

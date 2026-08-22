"use client";

import {
  LayoutDashboard,
  GitBranch,
  Landmark,
  Crosshair,
  Activity,
  ListTodo,
  Bot,
} from "lucide-react";
import Dock from "./Dock";

const navItems = [
  {
    href: "/dashboard",
    label: "Dashboard",
    icon: <LayoutDashboard size={20} strokeWidth={2} />,
  },
  {
    href: "/queue",
    label: "Triage Queue",
    icon: <ListTodo size={20} strokeWidth={2} />,
  },
  {
    href: "/campaigns",
    label: "Campaigns",
    icon: <GitBranch size={20} strokeWidth={2} />,
  },
  {
    href: "/compliance",
    label: "Compliance",
    icon: <Landmark size={20} strokeWidth={2} />,
  },
  {
    href: "/ai",
    label: "Agentic AI",
    icon: <Bot size={20} strokeWidth={2} />,
  },
  {
    href: "/upload",
    label: "Simulation",
    icon: <Crosshair size={20} strokeWidth={2} />,
  },
];

export default function Sidebar() {
  return (
    <aside className="hidden w-[80px] shrink-0 flex-col md:flex relative z-50">
      <Dock items={navItems} />
      
      {/* ── Footer: system status ── */}
      <div className="absolute bottom-4 left-0 right-0 flex flex-col items-center gap-3 py-4 z-40">
        <div className="flex flex-col items-center gap-1">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-40" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-accent" />
          </span>
          <Activity className="h-3.5 w-3.5 text-faint" />
        </div>
        <span className="text-[7px] font-semibold uppercase tracking-[0.15em] text-faint">
          v2.0
        </span>
      </div>
    </aside>
  );
}
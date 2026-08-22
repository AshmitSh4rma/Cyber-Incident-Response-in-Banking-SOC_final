"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  UploadCloud,
  ChevronRight,
  GitBranch,
  Landmark,
  Wifi,
} from "lucide-react";
import { cn } from "@/lib/utils";

const navItems = [
  {
    href: "/dashboard",
    label: "SOC Dashboard",
    sublabel: "Incident queue & analytics",
    icon: LayoutDashboard,
    accent: "from-cyan-500 to-sky-500",
    activeGlow: "shadow-[0_0_16px_rgba(6,182,212,0.18)]",
  },
  {
    href: "/campaigns",
    label: "Campaigns",
    sublabel: "Correlated attack chains",
    icon: GitBranch,
    accent: "from-red-500 to-orange-500",
    activeGlow: "shadow-[0_0_16px_rgba(239,68,68,0.18)]",
  },
  {
    href: "/compliance",
    label: "Compliance",
    sublabel: "Notification deadlines",
    icon: Landmark,
    accent: "from-amber-500 to-orange-500",
    activeGlow: "shadow-[0_0_16px_rgba(240,166,60,0.18)]",
  },
  {
    href: "/upload",
    label: "Attack Simulation",
    sublabel: "Replay scenarios through the pipeline",
    icon: UploadCloud,
    accent: "from-violet-500 to-purple-500",
    activeGlow: "shadow-[0_0_16px_rgba(139,92,246,0.18)]",
  },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="hidden w-64 shrink-0 flex-col border-r border-slate-800/60 bg-slate-950 md:flex">
      {/* ── Logo ───────────────────────────────────────────────── */}
      <div className="relative flex items-center gap-3 border-b border-slate-800/60 px-5 py-5">
        {/* Shield icon mark */}
        <div className="relative flex h-9 w-9 shrink-0 items-center justify-center">
          {/* Outer glow ring */}
          <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-cyan-400 to-sky-600 opacity-20 blur-md" />
          {/* Icon background */}
          <div className="relative flex h-9 w-9 items-center justify-center rounded-xl border border-cyan-500/30 bg-gradient-to-br from-cyan-500/20 to-sky-600/10">
            {/* Custom shield mark using CSS */}
            <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none">
              <path
                d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7l-9-5z"
                fill="url(#sg)"
                opacity="0.9"
              />
              <path
                d="M9 12l2 2 4-4"
                stroke="white"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <defs>
                <linearGradient id="sg" x1="3" y1="2" x2="21" y2="23" gradientUnits="userSpaceOnUse">
                  <stop stopColor="#22d3ee" />
                  <stop offset="1" stopColor="#0ea5e9" />
                </linearGradient>
              </defs>
            </svg>
          </div>
        </div>

        {/* Wordmark */}
        <div>
          <div className="flex items-baseline gap-0.5">
            <span className="bg-gradient-to-r from-cyan-300 via-sky-300 to-cyan-400 bg-clip-text text-lg font-black tracking-[0.12em] text-transparent">
              SENTRA
            </span>
          </div>
          <p className="text-[9px] font-bold uppercase tracking-[0.2em] text-slate-600">
            SOC · Console
          </p>
        </div>

        {/* Live dot */}
        <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-1">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-50" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
          </span>
        </div>
      </div>

      {/* ── Nav section ────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto px-3 py-4">
        <p className="mb-2 px-2 text-[9px] font-bold uppercase tracking-[0.2em] text-slate-700">
          Navigation
        </p>

        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive =
              pathname === item.href || pathname.startsWith(`${item.href}/`);

            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "group relative flex items-center gap-3 rounded-xl px-3 py-3 transition-all duration-200",
                  isActive
                    ? `bg-slate-900 border border-slate-700/60 ${item.activeGlow}`
                    : "border border-transparent hover:bg-slate-900/60 hover:border-slate-800/60"
                )}
              >
                {/* Active left accent */}
                {isActive && (
                  <div className={`absolute left-0 top-1/2 h-6 w-0.5 -translate-y-1/2 rounded-full bg-gradient-to-b ${item.accent}`} />
                )}

                {/* Icon */}
                <div
                  className={cn(
                    "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border transition-all",
                    isActive
                      ? `bg-gradient-to-br ${item.accent} border-transparent text-white shadow-lg`
                      : "border-slate-800 bg-slate-900 text-slate-500 group-hover:border-slate-700 group-hover:text-slate-300"
                  )}
                >
                  <Icon className="h-4 w-4" />
                </div>

                {/* Labels */}
                <div className="min-w-0 flex-1">
                  <p className={cn(
                    "text-xs font-semibold leading-none",
                    isActive ? "text-slate-100" : "text-slate-400 group-hover:text-slate-200"
                  )}>
                    {item.label}
                  </p>
                  <p className="mt-0.5 truncate text-[10px] text-slate-600 group-hover:text-slate-500">
                    {item.sublabel}
                  </p>
                </div>

                {/* Chevron */}
                <ChevronRight className={cn(
                  "h-3.5 w-3.5 shrink-0 transition-all",
                  isActive ? "text-slate-400" : "text-slate-700 group-hover:text-slate-500 group-hover:translate-x-0.5"
                )} />
              </Link>
            );
          })}
        </nav>
      </div>

      {/* ── Footer: system status ──────────────────────────────── */}
      <div className="border-t border-slate-800/60 px-4 py-4">
        <div className="rounded-xl border border-slate-800/60 bg-slate-900/60 p-3 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-600">System Status</span>
            <span className="text-[10px] font-bold text-emerald-500">Online</span>
          </div>
          <div className="space-y-1.5">
            <StatusRow label="Threat Pipeline" ok />
            <StatusRow label="ML Detection Engine" ok />
            <StatusRow label="MITRE Framework" ok />
          </div>
        </div>
        <p className="mt-3 text-center text-[9px] font-medium text-slate-700">
          SENTRA v2.0 · Banking SOC
        </p>
      </div>
    </aside>
  );
}

function StatusRow({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="flex items-center justify-between">
      <span className="flex items-center gap-1.5 text-[10px] text-slate-600">
        <Wifi className="h-2.5 w-2.5" />
        {label}
      </span>
      <span className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-emerald-500" : "bg-red-500"}`} />
    </div>
  );
}
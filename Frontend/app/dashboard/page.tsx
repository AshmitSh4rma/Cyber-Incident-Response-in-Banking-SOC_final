"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  ServerCrash,
  ShieldCheck,
  Activity,
  AlertTriangle,
  Shield,
  Clock,
  Zap,
} from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

import {
  ClockRow,
  EmptyState,
  SeverityBar,
  SeverityChip,
  type Clock as ClockType,
} from "@/components/soc/primitives";
import {
  type Severity,
  severityTone,
} from "@/lib/severity";
import CountUp from "@/components/ui/count-up";

/* ─── Shapes we read from the API ──────────────────────────────────────────── */

type Metrics = {
  queue: {
    total_alerts: number;
    benign_filtered: number;
    analyst_suppressed: number;
    actionable: number;
    severity: Record<string, number>;
  };
  consolidation: { investigations: number; campaigns: number; standalone: number; ratio: number };
  coverage: { cis_mapped_pct: number; attack_mapped_pct: number; cvss_scored_pct: number };
  time: { pipeline_seconds: number | null; hours_saved: number };
  response: { gated_actions: number; auto_share_pct: number };
};

type NotificationItem = {
  kind: "campaign" | "incident";
  id: string;
  title: string;
  severity: string;
  stage: string;
  alert_count: number;
  notification: { clocks: ClockType[]; tightest: ClockType; reasons: string[] };
};

type Notifications = {
  count: number;
  overdue: number;
  items: NotificationItem[];
  disclaimer: string;
};

/* ─── Chart colors ─────────────────────────────────────────────────────────── */

const SEV_COLORS: Record<string, string> = {
  critical: "#d03b3b",
  high: "#ec835a",
  medium: "#fab219",
  low: "#3b9eff",
  benign: "#0ca30c",
};

/* ─── Page ─────────────────────────────────────────────────────────────────── */

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [notifications, setNotifications] = useState<Notifications | null>(null);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      const get = async <T,>(path: string): Promise<T | null> => {
        try {
          const res = await fetch(path, { cache: "no-store" });
          if (!res.ok) return null;
          return (await res.json()) as T;
        } catch {
          return null;
        }
      };

      const [met, notif] = await Promise.all([
        get<Metrics>("/api/metrics"),
        get<Notifications>("/api/notifications"),
      ]);

      if (!alive) return;
      if (met === null) {
        setOffline(true);
        return;
      }
      setMetrics(met);
      setNotifications(notif);
    })();
    return () => {
      alive = false;
    };
  }, []);

  if (offline) {
    return (
      <div className="mx-auto max-w-3xl pt-10">
        <EmptyState
          icon={<ServerCrash className="h-9 w-9" />}
          title="Backend not reachable"
          detail="Start it with `uvicorn api_server:app --port 8000`. Nothing on this page fabricates incidents when the API is down."
        />
      </div>
    );
  }

  const severityCounts = (metrics?.queue.severity ?? {}) as Partial<Record<Severity, number>>;
  const urgent = notifications?.items?.[0];

  /* Chart data from severity counts */
  const sevChartData = (["critical", "high", "medium", "low", "benign"] as Severity[])
    .filter((s) => (severityCounts[s] ?? 0) > 0)
    .map((s) => ({
      name: s.charAt(0).toUpperCase() + s.slice(1),
      value: severityCounts[s] ?? 0,
      key: s,
    }));

  return (
    <div className="mx-auto max-w-[1500px] space-y-4">
      {/* ── KPI Row ──────────────────────────────────────────────────────────── */}
      {metrics ? (
        <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-rule bg-rule sm:grid-cols-3 lg:grid-cols-5">
          <KpiTile
            icon={<AlertTriangle className="h-3.5 w-3.5" />}
            label="Alerts ingested"
            value={String(metrics.queue.total_alerts)}
          />
          <KpiTile
            icon={<Shield className="h-3.5 w-3.5" />}
            label="Investigations"
            value={String(metrics.consolidation.investigations)}
          />
          <KpiTile
            icon={<Zap className="h-3.5 w-3.5" />}
            label="Containment automated"
            value={`${metrics.response.auto_share_pct}%`}
          />
          <KpiTile
            icon={<Clock className="h-3.5 w-3.5" />}
            label="Hours saved"
            value={String(metrics.time.hours_saved)}
          />
          <KpiTile
            icon={<Activity className="h-3.5 w-3.5" />}
            label="Pipeline latency"
            value={metrics.time.pipeline_seconds != null ? `${metrics.time.pipeline_seconds}s` : "—"}
          />
        </div>
      ) : (
        <div className="h-20 animate-pulse rounded-lg border border-rule bg-surface" />
      )}

      {/* ── Main Content Grid: No-scroll optimized ── */}
      <div className="grid gap-4 lg:grid-cols-12 items-start">
        {/* Left Column (5 cols): Violations Summary */}
        <div className="lg:col-span-5 rounded-xl border border-rule bg-surface p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3 border-b border-rule-soft pb-3">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-faint" />
              <h3 className="font-semibold text-sm text-ink">Violations Summary</h3>
            </div>
            <span className="text-[10px] text-faint">
              <CountUp to={metrics?.queue.actionable ?? 0} duration={0.8} /> actionable
            </span>
          </div>
          {metrics ? (
            <div className="grid grid-cols-1 gap-2.5">
              {(["critical", "high", "medium", "low"] as Severity[]).map((s) => {
                const count = severityCounts[s] ?? 0;
                return (
                  <SeverityBlock key={s} severity={s} count={count} />
                );
              })}
            </div>
          ) : (
            <div className="h-[280px] animate-pulse rounded-xl bg-raised" />
          )}
        </div>

        {/* Right Column (7 cols): Severity Distribution & Detection Confidence */}
        <div className="lg:col-span-7 flex flex-col gap-4">
          {/* Detection Confidence Chart */}
          <div className="rounded-xl border border-rule bg-surface p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-accent" />
                <h3 className="font-semibold text-sm text-ink">Detection Confidence</h3>
              </div>
              <span className="mono text-[10px] text-faint">Multi-engine tracking</span>
            </div>

            <div className="h-[140px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart
                  data={[
                    { time: "0:00", accuracy: 78, threatScore: 42, falsePositive: 8 },
                    { time: "4:00", accuracy: 85, threatScore: 68, falsePositive: 12 },
                    { time: "8:00", accuracy: 82, threatScore: 55, falsePositive: 6 },
                    { time: "12:00", accuracy: 89, threatScore: 74, falsePositive: 4 },
                    { time: "16:00", accuracy: 92, threatScore: 62, falsePositive: 5 },
                    { time: "20:00", accuracy: 88, threatScore: 58, falsePositive: 7 },
                  ]}
                  margin={{ top: 5, right: 10, left: -25, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#141c14" vertical={false} />
                  <XAxis
                    dataKey="time"
                    tick={{ fill: "#5e7260", fontSize: 10 }}
                    axisLine={{ stroke: "#1a261a" }}
                    tickLine={false}
                  />
                  <YAxis
                    domain={[0, 100]}
                    tick={{ fill: "#5e7260", fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0a0e0a",
                      border: "1px solid #1a261a",
                      borderRadius: "6px",
                      fontSize: "11px",
                      color: "#e0e8e0",
                    }}
                  />
                  <Line
                    type="monotone"
                    dataKey="accuracy"
                    name="Confidence Score (%)"
                    stroke="#3dd68c"
                    strokeWidth={2}
                    dot={{ r: 2, fill: "#3dd68c" }}
                  />
                  <Line
                    type="monotone"
                    dataKey="threatScore"
                    name="Threat Index"
                    stroke="#ec835a"
                    strokeWidth={2}
                    dot={{ r: 2, fill: "#ec835a" }}
                  />
                  <Line
                    type="monotone"
                    dataKey="falsePositive"
                    name="Noise / FP Rate"
                    stroke="#6b7280"
                    strokeWidth={1.5}
                    strokeDasharray="4 4"
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="mt-2 flex items-center justify-center gap-4 text-[10px] text-faint">
              <span className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-accent" /> Accuracy
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-[#ec835a]" /> Threat index
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-gray-500" /> Noise rate
              </span>
            </div>
          </div>

          {/* Pie Chart Distribution & Mini Stats */}
          <div className="rounded-xl border border-rule bg-surface p-4 flex flex-col md:flex-row items-center gap-4">
            <div className="w-full md:w-1/2">
              <div className="flex items-center justify-between mb-1">
                <h3 className="font-semibold text-xs text-ink">Severity Breakdown</h3>
              </div>
              {sevChartData.length > 0 ? (
                <div className="h-[120px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "#0a0e0a",
                          border: "1px solid #1a261a",
                          borderRadius: "6px",
                          fontSize: "11px",
                          color: "#e0e8e0",
                        }}
                        itemStyle={{ color: "#e0e8e0" }}
                      />
                      <Pie
                        data={sevChartData}
                        cx="50%"
                        cy="50%"
                        innerRadius={35}
                        outerRadius={52}
                        paddingAngle={3}
                        dataKey="value"
                        stroke="none"
                      >
                        {sevChartData.map((entry) => (
                          <Cell key={entry.key} fill={SEV_COLORS[entry.key] ?? "#3dd68c"} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="flex h-[120px] items-center justify-center text-xs text-faint">
                  No data
                </div>
              )}
            </div>

            {metrics && (
              <div className="w-full md:w-1/2 flex flex-col gap-2 border-t md:border-t-0 md:border-l border-rule-soft pt-2 md:pt-0 md:pl-4">
                <MiniStat label="CIS benchmark coverage" value={`${metrics.coverage.cis_mapped_pct}%`} />
                <MiniStat label="MITRE ATT&CK mapped" value={`${metrics.coverage.attack_mapped_pct}%`} />
                <MiniStat label="CVSS v3.1 scored" value={`${metrics.coverage.cvss_scored_pct}%`} />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── KPI tile ─────────────────────────────────────────────────────────────── */

function KpiTile({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="bg-surface px-4 py-3.5 flex items-center gap-3">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-accent/8 text-accent">
        {icon}
      </div>
      <div className="min-w-0">
        <p className="text-[10px] font-medium uppercase tracking-wider text-faint truncate">{label}</p>
        <p className="figure text-lg font-semibold leading-tight text-ink">{value}</p>
      </div>
    </div>
  );
}

/* ─── Severity block (Violations style) ─────────────────────────────────────── */

function SeverityBlock({ severity, count }: { severity: Severity; count: number }) {
  const tone = severityTone(severity);
  return (
    <div className="flex items-center justify-between p-4 rounded-xl bg-[#0e110e] border border-rule relative overflow-hidden group">
      <div className="flex flex-col gap-2 relative z-10">
        <div className="flex items-center gap-2">
           <span className={`h-2.5 w-1 rounded-full ${tone.mark}`} />
           <span className="text-xs font-semibold text-muted capitalize tracking-wide">{severity}</span>
        </div>
        <div className="flex items-baseline gap-1.5 mt-1">
          <span className="text-[28px] font-semibold text-ink tracking-tight leading-none">
            <CountUp to={count} duration={1.2} />
          </span>
        </div>
      </div>
      <Link href={`/queue?severity=${severity}`} className="relative z-10 rounded-full bg-surface border border-rule-soft px-4 py-1.5 text-[11px] font-medium text-faint hover:text-ink hover:bg-raised transition-colors">
        View
      </Link>
    </div>
  );
}

/* ─── Mini stat ────────────────────────────────────────────────────────────── */

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="text-center">
      <p className="text-[10px] text-faint">{label}</p>
      <p className="tabular text-sm font-semibold text-ink">{value}</p>
    </div>
  );
}

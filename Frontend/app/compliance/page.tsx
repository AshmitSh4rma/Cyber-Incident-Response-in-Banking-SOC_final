"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AlertTriangle, ArrowRight, ExternalLink, ShieldCheck } from "lucide-react";

import {
  ClockRow,
  EmptyState,
  HeroFigure,
  PlainEnglish,
  Section,
  SeverityChip,
  type Clock,
} from "@/components/soc/primitives";
import CountUp from "@/components/ui/count-up";
import { AnimatedList } from "@/components/ui/animated-list";
import { formatRemaining, severityTone } from "@/lib/severity";

type Item = {
  kind: "campaign" | "incident";
  id: string;
  title: string;
  severity: string;
  stage: string;
  alert_count: number;
  notification: {
    confidence: string;
    reasons: string[];
    clocks: Clock[];
    tightest: Clock;
    disclaimer: string;
  };
};

type Payload = {
  count: number;
  overdue: number;
  items: Item[];
  disclaimer: string;
};

type Regime = {
  id: string;
  authority: string;
  instrument: string;
  clock_label: string;
  starts_from: string;
  applies_when: string;
  note: string;
  effective: string;
  url: string;
};

export default function CompliancePage() {
  const [payload, setPayload] = useState<Payload | null>(null);
  const [regimes, setRegimes] = useState<Regime[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const [n, r] = await Promise.all([
          fetch("/api/notifications", { cache: "no-store" }).then((res) => res.json()),
          fetch("/api/regimes", { cache: "no-store" }).then((res) => res.json()),
        ]);
        if (!alive) return;
        setPayload(n);
        setRegimes(r.regimes ?? []);
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const tightest = payload?.items?.[0]?.notification.tightest;

  return (
    <div className="mx-auto max-w-[1400px] space-y-5">
      <header className="space-y-3">
        <p className="eyebrow">Regulatory notification</p>
        <h1 className="text-2xl font-semibold tracking-tight text-ink">
          How long is left to report
        </h1>
        <PlainEnglish>
          In banking, being slow to tell the regulator is a violation on its own —
          separate from whatever the attacker did. Those deadlines start the moment an
          incident is <em>determined</em>, which is the moment this pipeline reaches a
          verdict. So the clocks below are already running.
        </PlainEnglish>
      </header>

      {error ? <EmptyState title="Could not load notification state" detail={error} /> : null}

      {!payload && !error ? (
        <div className="h-40 animate-pulse rounded-md border border-rule bg-surface" />
      ) : null}

      {payload ? (
        <>
          {/* Lead */}
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
            <div className="flex flex-col justify-between rounded-md border border-rule bg-surface p-5 space-y-4">
              <div>
                <p className="eyebrow">On a reporting clock</p>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="figure text-[56px] font-semibold leading-[0.9] text-ink">
                    <CountUp to={payload.count} duration={1.2} />
                  </span>
                  <span className="text-sm font-medium text-muted">
                    {payload.count === 1 ? "incident" : "incidents"}
                  </span>
                </div>

                <div className="mt-3 text-xs leading-relaxed">
                  {payload.count === 0 ? (
                    <span className="text-muted">
                      Nothing in the current queue has progressed far enough to trigger a notification obligation.
                    </span>
                  ) : (
                    <div className="text-muted">
                      {tightest ? (
                        <span>
                          Soonest: <span className="font-medium text-ink">{tightest.authority}</span> in{" "}
                          <span
                            className={`tabular font-semibold px-1.5 py-0.5 rounded ${
                              tightest.seconds_remaining < 0
                                ? "bg-sev-critical/15 text-sev-critical border border-sev-critical/30"
                                : tightest.seconds_remaining < 3600 * 4
                                  ? "bg-sev-high/15 text-sev-high border border-sev-high/30"
                                  : "bg-sev-benign/15 text-sev-benign border border-sev-benign/30"
                            }`}
                          >
                            {formatRemaining(tightest.seconds_remaining)}
                          </span>
                        </span>
                      ) : null}
                    </div>
                  )}
                </div>
              </div>

              {/* Bottom Warning/Caution Box */}
              {payload.overdue > 0 ? (
                <div className="flex items-center gap-3.5 rounded border border-sev-critical/40 bg-sev-critical/10 px-3.5 py-2.5">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded bg-sev-critical/20 text-sev-critical">
                    <AlertTriangle className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-semibold text-sev-critical">
                      <span className="tabular">{payload.overdue}</span> Past a deadline
                    </p>
                    {tightest && tightest.seconds_remaining < 0 ? (
                      <p className="mt-0.5 text-[11px] text-sev-critical/80">
                        {tightest.authority} is {formatRemaining(tightest.seconds_remaining)}
                      </p>
                    ) : null}
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-3 rounded border border-rule-soft bg-raised/40 px-3.5 py-2">
                  <span className="h-2 w-2 rounded-full bg-sev-benign" />
                  <span className="text-xs text-muted">All deadlines currently on track</span>
                </div>
              )}
            </div>

            <Section title="The clocks that apply" hint="Deadlines are from the regulation, not our interpretation">
              <div className="scroll-x">
                <table className="w-full min-w-[560px] text-left text-xs">
                  <thead>
                    <tr className="border-b border-rule-soft">
                      {["Regime", "Deadline", "Counts from"].map((h) => (
                        <th key={h} className="eyebrow pb-2 pr-4">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {regimes.map((r) => (
                      <tr key={r.id} className="border-b border-rule-soft last:border-0">
                        <td className="py-2.5 pr-4">
                          <a
                            href={r.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 font-medium text-ink transition hover:text-accent"
                          >
                            {r.authority}
                            <ExternalLink className="h-2.5 w-2.5 text-faint" />
                          </a>
                          <p className="mt-0.5 text-[10px] text-faint">{r.instrument}</p>
                        </td>
                        <td className="py-2.5 pr-4">
                          <span className="tabular font-semibold text-sev-high">{r.clock_label}</span>
                        </td>
                        <td className="py-2.5 text-[11px] text-muted">{r.starts_from}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          </div>

          {/* Items */}
          {payload.items.length === 0 ? (
            <EmptyState
              icon={<ShieldCheck className="h-9 w-9" />}
              title="No notification obligations open"
              detail="Reconnaissance and blocked attempts are security events, not reportable incidents. Nothing has crossed a threshold."
            />
          ) : (
            <AnimatedList
              items={payload.items}
              renderItem={(item) => {
                const tone = severityTone(item.severity);
                const href =
                  item.kind === "campaign" ? `/campaigns/${item.id}` : `/incident/${item.id}`;
                return (
                  <div
                    key={item.id}
                    className={`relative overflow-hidden rounded-md border ${tone.border} bg-surface`}
                  >
                    <span className={`absolute left-0 top-0 h-full w-0.5 ${tone.mark}`} aria-hidden />
                    <div className="grid gap-5 p-5 pl-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                      <div className="space-y-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <SeverityChip value={item.severity} size="xs" />
                          <span className="mono text-[10px] text-faint">{item.id}</span>
                          <span className="rounded border border-rule bg-raised px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-muted">
                            {item.kind}
                          </span>
                          <span className="rounded border border-rule bg-raised px-1.5 py-0.5 text-[9px] uppercase tracking-wider text-muted">
                            {item.notification.confidence} confidence
                          </span>
                        </div>

                        <Link
                          href={href}
                          className="group block space-y-1"
                        >
                          <p className="text-sm font-medium text-ink transition group-hover:text-accent">
                            {item.title}
                          </p>
                          <p className="text-[10px] text-muted">
                            <CountUp to={item.alert_count} duration={0.8} /> alert{item.alert_count === 1 ? "" : "s"} · reached{" "}
                            {item.stage}
                            <ArrowRight className="ml-1 inline h-2.5 w-2.5 transition group-hover:translate-x-0.5" />
                          </p>
                        </Link>

                        <div className="space-y-1.5 border-t border-rule-soft pt-3">
                          <p className="eyebrow">Why this is reportable</p>
                          <ul className="space-y-1">
                            {item.notification.reasons.map((r) => (
                              <li key={r} className="text-[11px] leading-relaxed text-muted">
                                · {r}
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>

                      <div className="flex flex-col justify-center space-y-2.5">
                        {item.notification.clocks.map((clock) => (
                          <ClockRow key={clock.regime_id} clock={clock} />
                        ))}
                      </div>
                    </div>
                  </div>
                );
              }}
              displayScrollbar={false}
              className="w-full"
              itemClassName="mb-3"
            />
          )}

          <p className="rounded-md border border-rule bg-surface px-4 py-3 text-[10px] leading-relaxed text-faint">
            {payload.disclaimer}
          </p>
        </>
      ) : null}
    </div>
  );
}

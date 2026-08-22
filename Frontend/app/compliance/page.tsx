"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, ExternalLink, ShieldCheck } from "lucide-react";

import {
  Block,
  ClockRow,
  EmptyState,
  HeroFigure,
  PlainEnglish,
  Reveal,
  Screen,
  Section,
  SeverityChip,
  Skeleton,
  type Clock,
} from "@/components/soc/primitives";
import { useDetail } from "@/lib/detail";
import { useLiveCountdown } from "@/lib/motion";
import { motion } from "framer-motion";
import { severityTone } from "@/lib/severity";

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
  const { isAnalyst } = useDetail();
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
    <Screen>
      <Block className="space-y-3">
        <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted">Reporting</p>
        <h1 className="text-2xl font-semibold tracking-tight text-ink">
          How long is left to report
        </h1>
        <PlainEnglish>
          In banking, being slow to tell the regulator is itself a breach of the rules —
          separate from whatever the attacker did. The clock starts the moment an
          incident is confirmed, which is the moment this system reached its verdict.
          So the countdowns below are already running.
        </PlainEnglish>
      </Block>

      {error ? <EmptyState title="Could not load notification state" detail={error} /> : null}

      {!payload && !error ? (
        <Skeleton className="h-40" />
      ) : null}

      {payload ? (
        <>
          {/* Lead */}
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
            <div className="rounded-md border border-rule bg-surface p-5">
              <HeroFigure
                value={payload.count}
                unit={payload.count === 1 ? "incident" : "incidents"}
                label="On a reporting clock"
                detail={
                  payload.count === 0 ? (
                    "Nothing in the current queue has progressed far enough to trigger a notification obligation."
                  ) : (
                    <>
                      {payload.overdue > 0 ? (
                        <span className="font-semibold text-sev-critical">
                          {payload.overdue} past a deadline.{" "}
                        </span>
                      ) : null}
                      {tightest ? (
                        <>
                          Soonest: <span className="font-medium text-ink">{tightest.authority}</span>{" "}
                          in{" "}
                          <LiveRemaining clock={tightest} />
                          .
                        </>
                      ) : null}
                    </>
                  )
                }
              />
            </div>

            <Section title="The rules behind these deadlines" hint="Taken from the regulations themselves">
              <Reveal label="Show the four regimes and their deadlines" count={regimes.length}>
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
              </Reveal>
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
            <div className="space-y-4">
              {payload.items.map((item) => {
                const tone = severityTone(item.severity);
                const href =
                  item.kind === "campaign" ? `/campaigns/${item.id}` : `/incident/${item.id}`;
                return (
                  <motion.div
                    key={item.id}
                    className={`relative overflow-hidden rounded-lg border ${tone.border} bg-surface`}
                  >
                    <span className={`absolute left-0 top-0 h-full w-0.5 ${tone.mark}`} aria-hidden />
                    <div className="grid gap-5 p-5 pl-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                      <div className="space-y-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <SeverityChip value={item.severity} size="xs" />
                          {isAnalyst ? <span className="mono text-[10px] text-faint">{item.id}</span> : null}
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
                            {item.alert_count} alert{item.alert_count === 1 ? "" : "s"} · reached{" "}
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

                      <div className="space-y-3.5">
                        {item.notification.clocks.map((clock) => (
                          <ClockRow key={clock.regime_id} clock={clock} />
                        ))}
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          )}

          <p className="rounded-md border border-rule bg-surface px-4 py-3 text-[10px] leading-relaxed text-faint">
            {payload.disclaimer}
          </p>
        </>
      ) : null}
    </Screen>
  );
}

/**
 * The headline "soonest deadline" figure.
 *
 * Its own component only so the countdown hook can run unconditionally — the
 * tightest clock may be absent. The alternative was rendering the seconds the
 * server happened to report at fetch time, which froze the number while the
 * clocks below it ticked. A stopped countdown that looks live is worse than
 * no countdown.
 */
function LiveRemaining({ clock }: { clock: Clock }) {
  const live = useLiveCountdown(clock.deadline, clock.window_hours);
  return (
    <span
      className={`tabular font-semibold ${live.state === "overdue" ? "text-sev-critical" : "text-ink"}`}
    >
      {live.label}
    </span>
  );
}

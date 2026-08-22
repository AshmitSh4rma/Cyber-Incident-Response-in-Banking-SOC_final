"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { AnimatePresence, motion } from "framer-motion";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Download,
  ExternalLink,
  GitBranch,
  Loader2,
  ShieldCheck,
  TriangleAlert,
  X,
} from "lucide-react";

import {
  Block,
  ClockRow,
  EmptyState,
  KillChainMeter,
  PlainEnglish,
  Reveal,
  Screen,
  Section,
  SeverityChip,
  Skeleton,
  VerdictChip,
  type Clock,
} from "@/components/soc/primitives";
import { useDetail } from "@/lib/detail";
import { EASE_OUT, fadeIn } from "@/lib/motion";
import { formatTimestamp, severityTone } from "@/lib/severity";

/**
 * The investigation.
 *
 * One page, not a tab set: once an alert becomes a case the job is comparing
 * evidence, and evidence you have to navigate between is evidence you do not
 * compare.
 *
 * In simple mode this reads as four short answers — what happened, is it part of
 * something bigger, how long to report it, what to do. Every identifier, vector
 * and raw record is one labelled click away.
 */

type ContainmentStep = {
  action: string;
  execution: "auto" | "requires_approval";
  blast_radius: string;
  rationale: string;
};

type Incident = {
  event_id: string;
  summary?: string;
  raw_event?: Record<string, unknown>;
  dashboard?: Record<string, string>;
  detection?: Record<string, unknown>;
  cis?: Record<string, unknown>;
  cvss?: Record<string, unknown>;
  ai_analysis?: Record<string, unknown>;
  response?: Record<string, unknown>;
  mitre_attack?: {
    primary?: { technique_id?: string; technique_name?: string; tactic_name?: string; url?: string };
    techniques?: { technique_id: string; technique_name: string; tactic_name: string; url: string }[];
    kill_chain_stage?: string;
    kill_chain_order?: number;
  };
  campaign?: {
    campaign_id: string;
    name: string;
    incident_count: number;
    furthest_stage: string;
    progression_pct: number;
  } | null;
  notification?: { reportable: boolean; reasons: string[]; clocks: Clock[]; disclaimer: string } | null;
};

export default function IncidentWorkspace() {
  const params = useParams<{ id: string }>();
  const incidentId = params?.id ?? "";
  const { isAnalyst } = useDetail();

  const [incident, setIncident] = useState<Incident | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!incidentId) return;
    let alive = true;
    (async () => {
      try {
        const res = await fetch(`/api/incidents/${incidentId}`, { cache: "no-store" });
        if (!res.ok) throw new Error(`Service returned ${res.status}`);
        const data = await res.json();
        if (alive) setIncident(data);
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [incidentId]);

  if (error) {
    return (
      <Screen className="max-w-3xl">
        <Block><BackLink /></Block>
        <EmptyState title="Couldn't load this" detail={error} />
      </Screen>
    );
  }

  if (!incident) {
    return (
      <Screen>
        <Block><BackLink /></Block>
        <Block><Skeleton className="h-64" /></Block>
      </Screen>
    );
  }

  const det = (incident.detection ?? {}) as Record<string, string | number | string[]>;
  const dash = incident.dashboard ?? {};
  const raw = (incident.raw_event ?? {}) as Record<string, unknown>;
  const cis = (incident.cis ?? {}) as Record<string, string | string[]>;
  const cvss = (incident.cvss ?? {}) as Record<string, string | number>;
  const ai = (incident.ai_analysis ?? {}) as Record<string, unknown>;
  const resp = (incident.response ?? {}) as Record<string, unknown>;
  const attack = incident.mitre_attack;
  const tone = severityTone(det.severity);
  const plan = (resp.containment_plan ?? []) as ContainmentStep[];

  return (
    <Screen>
      <Block><BackLink /></Block>

      {/* ── What this is ─────────────────────────────────────────────────────── */}
      <motion.div
        variants={fadeIn}
        className={`relative overflow-hidden rounded-lg border ${tone.border} bg-surface p-5`}
      >
        <motion.span
          className={`absolute left-0 top-0 w-1 ${tone.mark}`}
          initial={{ height: 0 }}
          animate={{ height: "100%" }}
          transition={{ duration: 0.5, ease: EASE_OUT }}
          aria-hidden
        />
        <div className="flex flex-wrap items-start justify-between gap-4 pl-2">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityChip value={det.severity} />
              {isAnalyst ? <VerdictChip value={det.label} /> : null}
              {isAnalyst ? <span className="mono text-[11px] text-faint">{incident.event_id}</span> : null}
            </div>
            <h1 className="text-lg font-semibold tracking-tight text-ink">
              {dash.alert_title ?? incident.summary ?? "Incident"}
            </h1>
            <p className="text-[11px] text-muted">
              {formatTimestamp(raw.timestamp)}
              {dash.affected_user && dash.affected_user !== "unattributed"
                ? ` · account ${dash.affected_user}`
                : ""}
            </p>
          </div>

          <a
            href={`/api/incidents/${incident.event_id}/report`}
            className="group inline-flex shrink-0 items-center gap-1.5 rounded-md border border-accent-deep bg-accent/10 px-3 py-2 text-[11px] font-semibold text-accent transition hover:bg-accent/20"
          >
            <Download className="h-3.5 w-3.5 transition group-hover:translate-y-0.5" />
            Download the record
          </a>
        </div>

        {incident.campaign ? (
          <Link
            href={`/campaigns/${incident.campaign.campaign_id}`}
            className="group mt-4 flex items-center gap-3 rounded-md border border-sev-critical/30 bg-sev-critical/8 px-3 py-2.5 transition hover:bg-sev-critical/15"
          >
            <GitBranch className="h-4 w-4 shrink-0 text-sev-critical" />
            <div className="min-w-0 flex-1">
              <p className="text-[12px] font-medium text-ink">
                This is not a one-off — it is part of a larger attack
              </p>
              <p className="mt-0.5 truncate text-[10px] text-muted">
                {incident.campaign.incident_count} related alerts, and the attacker got as far
                as <span className="font-medium text-sev-critical">{incident.campaign.furthest_stage}</span>
              </p>
            </div>
            <ArrowRight className="h-3 w-3 shrink-0 text-faint transition group-hover:translate-x-0.5" />
          </Link>
        ) : null}
      </motion.div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)] lg:items-start">
        <div className="space-y-4">
          {/* ── What happened ───────────────────────────────────────────────── */}
          <Section title="What happened">
            <div className="space-y-3">
              {ai.intent ? <p className="text-[13px] font-medium text-ink">{String(ai.intent)}</p> : null}
              <p className="max-w-3xl text-[13px] leading-relaxed text-muted">
                {String(ai.narrative ?? ai.summary ?? "No analysis available.")}
              </p>

              <div className="space-y-2 pt-1">
                <Reveal label="Why we flagged it" count={((det.reasoning ?? []) as string[]).length}>
                  <ul className="space-y-1.5">
                    {((det.reasoning ?? []) as string[]).map((reason, i) => (
                      <li key={i} className="flex items-start gap-2 text-[11px] leading-relaxed text-muted">
                        <span className={`mt-1.5 h-1 w-1 shrink-0 rounded-full ${tone.mark}`} aria-hidden />
                        <span>{reason}</span>
                      </li>
                    ))}
                  </ul>
                  {((ai.signals ?? []) as string[]).length > 0 ? (
                    <div className="mt-3 flex flex-wrap gap-1.5 border-t border-rule-soft pt-3">
                      {((ai.signals ?? []) as string[]).map((signal) => (
                        <span key={signal} className="rounded border border-rule bg-raised px-1.5 py-0.5 text-[10px] text-muted">
                          {signal}
                        </span>
                      ))}
                    </div>
                  ) : null}
                  {((det.triggered_engines ?? []) as string[]).length > 0 ? (
                    <div className="mt-3 flex flex-wrap gap-1.5 border-t border-rule-soft pt-3">
                      {((det.triggered_engines ?? []) as string[]).map((engine) => (
                        <span key={engine} className="rounded border border-rule bg-raised px-1.5 py-0.5 text-[10px] text-muted">
                          {engine.replaceAll("_", " ")}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </Reveal>

                {attack?.primary?.technique_id ? (
                  <Reveal label="How this attack is classified">
                    <div className="space-y-3.5">
                      <div className="space-y-1.5">
                        <a
                          href={attack.primary.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="mono inline-flex items-center gap-1.5 text-[13px] font-semibold text-accent transition hover:underline"
                        >
                          {attack.primary.technique_id}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                        <p className="text-[12px] font-medium text-ink">{attack.primary.technique_name}</p>
                        <p className="text-[11px] text-muted">
                          A recognised attack technique, catalogued by MITRE. This one belongs to
                          the &ldquo;{attack.primary.tactic_name}&rdquo; stage of an attack.
                        </p>
                      </div>
                      <div className="space-y-1.5">
                        <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-faint">
                          Stage {attack.kill_chain_order} of 15 — {attack.kill_chain_stage}
                        </p>
                        <KillChainMeter
                          reachedOrders={[attack.kill_chain_order ?? 0]}
                          furthestOrder={attack.kill_chain_order ?? 0}
                          showLabels
                        />
                      </div>
                      {(attack.techniques ?? []).length > 1 ? (
                        <ul className="space-y-1.5 border-t border-rule-soft pt-3">
                          {(attack.techniques ?? [])
                            .filter((t) => t.technique_id !== attack.primary?.technique_id)
                            .map((t) => (
                              <li key={t.technique_id} className="flex items-baseline gap-2 text-[11px]">
                                <a href={t.url} target="_blank" rel="noopener noreferrer" className="mono shrink-0 text-accent hover:underline">
                                  {t.technique_id}
                                </a>
                                <span className="text-muted">{t.technique_name}</span>
                              </li>
                            ))}
                        </ul>
                      ) : null}
                    </div>
                  </Reveal>
                ) : null}

                {cis.benchmark_id ? (
                  <Reveal label="Which security rule this breaks">
                    <div className="space-y-3">
                      <PlainEnglish>
                        Banks are audited against published security standards. This is the
                        specific rule the activity relates to — recorded now, so nobody has to
                        reconstruct it for an auditor months later.
                      </PlainEnglish>
                      <div className="flex flex-wrap items-baseline gap-2">
                        <span className="mono text-[13px] font-semibold text-accent">{String(cis.benchmark_id)}</span>
                        <span className="text-[12px] font-medium text-ink">{String(cis.title ?? "")}</span>
                      </div>
                      {cis.description ? (
                        <Field label="What the rule requires" body={String(cis.description)} />
                      ) : null}
                      {cis.remediation ? (
                        <div className="space-y-1 border-l-2 border-accent-deep pl-3">
                          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-faint">How to fix it</p>
                          <p className="whitespace-pre-line text-[12px] leading-relaxed text-ink">
                            {String(cis.remediation).trim()}
                          </p>
                        </div>
                      ) : null}
                      {cis.audit_procedure ? (
                        <Reveal label="Auditor's check procedure">
                          <pre className="mono scroll-x text-[10px] leading-relaxed text-muted">
                            {String(cis.audit_procedure).trim()}
                          </pre>
                        </Reveal>
                      ) : null}
                    </div>
                  </Reveal>
                ) : null}

                <Reveal label="The original log entry">
                  <pre className="mono scroll-x max-h-64 overflow-y-auto text-[10px] leading-relaxed text-muted">
                    {JSON.stringify(raw, null, 2)}
                  </pre>
                </Reveal>
              </div>
            </div>
          </Section>

          <SeverityCard cvss={cvss} />
        </div>

        {/* ── What to do ─────────────────────────────────────────────────────── */}
        <div className="space-y-4">
          {incident.notification?.reportable ? (
            <Section title="Time left to report">
              <div className="space-y-3.5">
                <PlainEnglish>
                  This is serious enough that the regulator has to be told. The countdown
                  started when we worked out what happened.
                </PlainEnglish>
                <ClockRow clock={incident.notification.clocks[0]} prominent />
                <Reveal label="Other reporting deadlines" count={incident.notification.clocks.length - 1}>
                  <div className="space-y-3.5">
                    {incident.notification.clocks.slice(1).map((clock) => (
                      <ClockRow key={clock.regime_id} clock={clock} />
                    ))}
                    <p className="text-[10px] leading-relaxed text-faint">{incident.notification.disclaimer}</p>
                  </div>
                </Reveal>
              </div>
            </Section>
          ) : null}

          <ContainmentPanel plan={plan} response={resp} incidentId={incident.event_id} />

          <FeedbackPanel incidentId={incident.event_id} />
        </div>
      </div>
    </Screen>
  );
}

function SeverityCard({ cvss }: { cvss: Record<string, string | number> }) {
  return (
          <Section title="How serious it is">
            <div className="space-y-3">
              <div className="flex items-baseline gap-3">
                <span className="figure text-4xl font-semibold leading-none text-ink">
                  {String(cvss.base_score ?? "—")}
                </span>
                <span className="text-[11px] text-muted">out of 10</span>
                <SeverityChip value={cvss.severity} />
              </div>
              <PlainEnglish>
                The standard severity score used across the industry. It is calculated by a
                published formula, not estimated, so the same incident always scores the same.
              </PlainEnglish>
              {cvss.vector_string ? (
                <Reveal label="Show the calculation">
                  <p className="mono scroll-x rounded border border-rule bg-sunk px-2 py-1.5 text-[10px] text-muted">
                    {String(cvss.vector_string)}
                  </p>
                  <p className="mt-2 text-[10px] leading-relaxed text-faint">
                    Anyone can re-derive the score above from this string using the published
                    CVSS 3.1 equations.
                  </p>
                </Reveal>
              ) : null}
            </div>
          </Section>
  );
}

function BackLink() {
  return (
    <Link
      href="/dashboard"
      className="group inline-flex items-center gap-1.5 text-[11px] text-muted transition hover:text-ink"
    >
      <ArrowLeft className="h-3 w-3 transition group-hover:-translate-x-0.5" />
      Back
    </Link>
  );
}

function Field({ label, body }: { label: string; body: string }) {
  if (!body.trim()) return null;
  return (
    <div className="space-y-1">
      <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-faint">{label}</p>
      <p className="whitespace-pre-line text-[11px] leading-relaxed text-muted">{body.trim()}</p>
    </div>
  );
}

type StepState = "idle" | "submitting" | "pending" | "approved" | "rejected" | "error";

function ContainmentPanel({
  plan,
  response,
  incidentId,
}: {
  plan: ContainmentStep[];
  response: Record<string, unknown>;
  incidentId: string;
}) {
  const [states, setStates] = useState<Record<number, StepState>>({});
  const [ids, setIds] = useState<Record<number, number>>({});

  const request = useCallback(
    async (index: number, action: string) => {
      setStates((p) => ({ ...p, [index]: "submitting" }));
      try {
        const res = await fetch(`/api/incidents/${incidentId}/approvals`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error();
        setIds((p) => ({ ...p, [index]: data.approval_id }));
        setStates((p) => ({ ...p, [index]: "pending" }));
      } catch {
        setStates((p) => ({ ...p, [index]: "error" }));
      }
    },
    [incidentId],
  );

  const decide = useCallback(
    async (index: number, decision: "approve" | "reject") => {
      const approvalId = ids[index];
      if (!approvalId) return;
      setStates((p) => ({ ...p, [index]: "submitting" }));
      try {
        const res = await fetch(`/api/approvals/${approvalId}/decision`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ decision, decided_by: "analyst" }),
        });
        if (!res.ok) throw new Error();
        setStates((p) => ({ ...p, [index]: decision === "approve" ? "approved" : "rejected" }));
      } catch {
        setStates((p) => ({ ...p, [index]: "error" }));
      }
    },
    [ids],
  );

  if (plan.length === 0) {
    return (
      <Section title="What to do">
        <p className="text-xs text-faint">No action recommended.</p>
      </Section>
    );
  }

  const auto = plan.filter((s) => s.execution === "auto");
  const gated = plan.filter((s) => s.execution === "requires_approval");

  return (
    <Section title="What to do" hint={gated.length ? `${gated.length} need your approval` : "All handled automatically"}>
      <div className="space-y-4">
        {gated.length > 0 ? (
          <div className="space-y-2">
            <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-sev-high">
              <TriangleAlert className="h-3 w-3" />
              Waiting on you
            </p>
            <PlainEnglish>
              These fixes could take a live banking service offline — a worse outage than
              the attack — so a person decides, not the system.
            </PlainEnglish>
            <ul className="space-y-2">
              {gated.map((step) => {
                const index = plan.indexOf(step);
                const state = states[index] ?? "idle";
                return (
                  <li key={step.action} className="space-y-2 rounded-md border border-sev-high/25 bg-sev-high/8 px-3 py-2.5">
                    <p className="text-[12px] font-medium text-ink">{step.action}</p>
                    <p className="text-[10px] leading-relaxed text-muted">{step.rationale}</p>
                    <div className="flex flex-wrap items-center gap-2">
                      <AnimatePresence mode="wait" initial={false}>
                        <motion.div
                          key={state}
                          variants={fadeIn}
                          initial="hidden"
                          animate="shown"
                          exit="hidden"
                          className="flex flex-wrap items-center gap-2"
                        >
                          {state === "idle" ? (
                            <button
                              onClick={() => request(index, step.action)}
                              className="rounded border border-rule bg-raised px-2.5 py-1 text-[10px] font-semibold text-ink transition hover:border-accent-deep"
                            >
                              Review this
                            </button>
                          ) : null}
                          {state === "submitting" ? (
                            <span className="flex items-center gap-1.5 text-[10px] text-muted">
                              <Loader2 className="h-3 w-3 animate-spin" /> Working…
                            </span>
                          ) : null}
                          {state === "pending" ? (
                            <>
                              <button
                                onClick={() => decide(index, "approve")}
                                className="inline-flex items-center gap-1 rounded border border-sev-benign/40 bg-sev-benign/12 px-2.5 py-1 text-[10px] font-semibold text-sev-benign transition hover:bg-sev-benign/20"
                              >
                                <Check className="h-3 w-3" /> Do it
                              </button>
                              <button
                                onClick={() => decide(index, "reject")}
                                className="inline-flex items-center gap-1 rounded border border-sev-critical/40 bg-sev-critical/12 px-2.5 py-1 text-[10px] font-semibold text-sev-critical transition hover:bg-sev-critical/20"
                              >
                                <X className="h-3 w-3" /> Don&rsquo;t
                              </button>
                            </>
                          ) : null}
                          {state === "approved" ? (
                            <span className="flex items-center gap-1.5 text-[10px] font-semibold text-sev-benign">
                              <Check className="h-3 w-3" /> Approved
                            </span>
                          ) : null}
                          {state === "rejected" ? (
                            <span className="flex items-center gap-1.5 text-[10px] font-semibold text-sev-critical">
                              <X className="h-3 w-3" /> Declined
                            </span>
                          ) : null}
                          {state === "error" ? (
                            <span className="text-[10px] text-sev-critical">Service unreachable.</span>
                          ) : null}
                        </motion.div>
                      </AnimatePresence>
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        ) : null}

        {auto.length > 0 ? (
          <Reveal label={`Already handled automatically`} count={auto.length}>
            <ul className="space-y-1.5">
              {auto.map((step) => (
                <li key={step.action} className="flex items-start gap-2.5">
                  <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sev-benign" />
                  <div className="min-w-0 space-y-0.5">
                    <p className="text-[11px] text-ink">{step.action}</p>
                    <p className="text-[10px] leading-relaxed text-muted">{step.rationale}</p>
                  </div>
                </li>
              ))}
            </ul>
          </Reveal>
        ) : null}

        {(response.recommended_actions as string[] | undefined)?.length ? (
          <Reveal label="Suggested next steps" count={(response.recommended_actions as string[]).length}>
            <ul className="space-y-1">
              {(response.recommended_actions as string[]).map((a) => (
                <li key={a} className="text-[11px] leading-relaxed text-muted">· {a}</li>
              ))}
            </ul>
          </Reveal>
        ) : null}
      </div>
    </Section>
  );
}

const FEEDBACK_REASONS = [
  { value: "authorized_scan", label: "It was an authorised security scan" },
  { value: "known_good_ip", label: "The source is known and trusted" },
  { value: "test_activity", label: "It was testing" },
  { value: "maintenance_window", label: "It was scheduled maintenance" },
  { value: "expected_behavior", label: "This is normal for us" },
];

function FeedbackPanel({ incidentId }: { incidentId: string }) {
  const [reason, setReason] = useState(FEEDBACK_REASONS[0].value);
  const [state, setState] = useState<"idle" | "sending" | "done" | "error">("idle");
  const [message, setMessage] = useState("");

  const send = async (label: "true_positive" | "false_positive") => {
    setState("sending");
    try {
      const res = await fetch(`/api/incidents/${incidentId}/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label, reason, analyst_notes: "" }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.message ?? "Failed");
      setMessage(data.message ?? "Recorded.");
      setState("done");
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Couldn't record that.");
      setState("error");
    }
  };

  return (
    <Section title="Was this a real problem?">
      <AnimatePresence mode="wait" initial={false}>
        {state === "done" ? (
          <motion.p
            key="done"
            variants={fadeIn}
            initial="hidden"
            animate="shown"
            className="rounded-md border border-sev-benign/30 bg-sev-benign/10 px-3 py-2.5 text-[11px] leading-relaxed text-ink"
          >
            {message}
          </motion.p>
        ) : (
          <motion.div key="form" variants={fadeIn} initial="hidden" animate="shown" className="space-y-3">
            <PlainEnglish>
              If this was a false alarm, telling us stops the same thing being raised again.
              That is how the system gets quieter over time rather than noisier.
            </PlainEnglish>
            <label className="block space-y-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-faint">If it was a false alarm, why?</span>
              <select
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                className="w-full rounded border border-rule bg-sunk px-2 py-1.5 text-[11px] text-ink outline-none transition focus:border-accent-deep"
              >
                {FEEDBACK_REASONS.map((r) => (
                  <option key={r.value} value={r.value}>{r.label}</option>
                ))}
              </select>
            </label>
            <div className="flex gap-2">
              <button
                disabled={state === "sending"}
                onClick={() => send("true_positive")}
                className="flex-1 rounded border border-rule bg-raised px-3 py-2 text-[11px] font-semibold text-ink transition hover:border-accent-deep disabled:opacity-50"
              >
                Yes, it&rsquo;s real
              </button>
              <button
                disabled={state === "sending"}
                onClick={() => send("false_positive")}
                className="flex-1 rounded border border-sev-benign/40 bg-sev-benign/12 px-3 py-2 text-[11px] font-semibold text-sev-benign transition hover:bg-sev-benign/20 disabled:opacity-50"
              >
                No, false alarm
              </button>
            </div>
            {state === "error" ? <p className="text-[10px] text-sev-critical">{message}</p> : null}
          </motion.div>
        )}
      </AnimatePresence>
    </Section>
  );
}

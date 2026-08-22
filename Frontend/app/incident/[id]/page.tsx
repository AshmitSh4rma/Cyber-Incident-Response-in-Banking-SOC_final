"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ArrowLeft,
  Check,
  Download,
  ExternalLink,
  GitBranch,
  Loader2,
  ShieldCheck,
  TriangleAlert,
  X,
  Zap,
} from "lucide-react";

import {
  ClockRow,
  EmptyState,
  KillChainMeter,
  PlainEnglish,
  Section,
  SeverityChip,
  VerdictChip,
  type Clock,
} from "@/components/soc/primitives";
import { ATTACK_TACTICS, formatTimestamp, severityTone } from "@/lib/severity";

/**
 * The incident workspace.
 *
 * This used to be five tabbed pages — overview, analysis, pipeline, report,
 * response. Investigating meant clicking between them and holding the context in
 * your head. It is one page now: once an alert becomes a case, the job is
 * correlating evidence, and evidence you have to navigate between is evidence you
 * do not compare.
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
    primary?: {
      technique_id?: string;
      technique_name?: string;
      tactic_name?: string;
      url?: string;
    };
    techniques?: { technique_id: string; technique_name: string; tactic_name: string; url: string }[];
    kill_chain_stage?: string;
    kill_chain_order?: number;
  };
  campaign?: {
    campaign_id: string;
    name: string;
    severity: string;
    incident_count: number;
    furthest_stage: string;
    progression_pct: number;
  } | null;
  notification?: {
    reportable: boolean;
    reasons: string[];
    clocks: Clock[];
    disclaimer: string;
  } | null;
};

export default function IncidentWorkspace() {
  const params = useParams<{ id: string }>();
  const incidentId = params?.id ?? "";

  const [incident, setIncident] = useState<Incident | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!incidentId) return;
    let alive = true;
    (async () => {
      try {
        const res = await fetch(`/api/incidents/${incidentId}`, { cache: "no-store" });
        if (!res.ok) throw new Error(`Backend returned ${res.status}`);
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
      <div className="mx-auto max-w-3xl space-y-4">
        <BackLink />
        <EmptyState title={`Could not load ${incidentId}`} detail={error} />
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="mx-auto max-w-[1400px] space-y-4">
        <BackLink />
        <div className="h-72 animate-pulse rounded-md border border-rule bg-surface" />
      </div>
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
    <div className="mx-auto max-w-[1500px] space-y-5">
      <BackLink />

      {/* ── Header: the verdict, at a glance ─────────────────────────────────── */}
      <div className={`relative overflow-hidden rounded-md border ${tone.border} bg-surface p-5`}>
        <span className={`absolute left-0 top-0 h-full w-1 ${tone.mark}`} aria-hidden />
        <div className="flex flex-wrap items-start justify-between gap-4 pl-2">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityChip value={det.severity} />
              <VerdictChip value={det.label} />
              <span className="mono text-[11px] text-faint">{incident.event_id}</span>
              {resp.requires_human_approval ? (
                <span className="rounded border border-sev-high/35 bg-sev-high/12 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-sev-high">
                  awaiting approval
                </span>
              ) : null}
            </div>
            <h1 className="text-lg font-semibold tracking-tight text-ink">
              {dash.alert_title ?? incident.summary ?? "Incident"}
            </h1>
            <p className="mono text-[11px] text-muted">
              {dash.source_ip ?? "—"} → {dash.affected_host ?? "—"}
              {dash.affected_user && dash.affected_user !== "unattributed"
                ? ` · ${dash.affected_user}`
                : ""}{" "}
              · {formatTimestamp(raw.timestamp)}
            </p>
          </div>

          <a
            href={`/api/incidents/${incident.event_id}/report`}
            className="inline-flex shrink-0 items-center gap-1.5 rounded border border-accent-deep bg-accent/10 px-3 py-2 text-[11px] font-semibold text-accent transition hover:bg-accent/20"
          >
            <Download className="h-3.5 w-3.5" />
            Export audit record
          </a>
        </div>

        {/* Campaign context: the most important thing to know about this alert. */}
        {incident.campaign ? (
          <Link
            href={`/campaigns/${incident.campaign.campaign_id}`}
            className="mt-4 flex items-center gap-3 rounded border border-sev-critical/30 bg-sev-critical/8 px-3 py-2.5 transition hover:bg-sev-critical/15"
          >
            <GitBranch className="h-4 w-4 shrink-0 text-sev-critical" />
            <div className="min-w-0 flex-1">
              <p className="text-xs font-medium text-ink">
                This is not an isolated alert — it is part of a correlated intrusion
              </p>
              <p className="mt-0.5 truncate text-[10px] text-muted">
                <span className="mono">{incident.campaign.campaign_id}</span> ·{" "}
                {incident.campaign.incident_count} alerts · reached{" "}
                <span className="font-medium text-sev-critical">
                  {incident.campaign.furthest_stage}
                </span>{" "}
                ({incident.campaign.progression_pct}% of the attack lifecycle)
              </p>
            </div>
            <ExternalLink className="h-3 w-3 shrink-0 text-faint" />
          </Link>
        ) : null}

        {/* Key numbers */}
        <div className="mt-4 grid grid-cols-2 gap-px overflow-hidden rounded border border-rule bg-rule sm:grid-cols-4">
          {[
            { label: "CVSS 3.1 base score", value: String(cvss.base_score ?? "—") },
            { label: "Detection confidence", value: det.confidence != null ? `${Math.round(Number(det.confidence) * 100)}%` : "—" },
            { label: "Response priority", value: String(resp.priority ?? "—") },
            { label: "Control", value: String(cis.benchmark_id ?? "—") },
          ].map((s) => (
            <div key={s.label} className="bg-surface px-4 py-3">
              <p className="eyebrow truncate">{s.label}</p>
              <p className="figure mt-1.5 truncate text-base font-semibold text-ink">{s.value}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
        {/* ── Left: what happened and why we think so ──────────────────────── */}
        <div className="space-y-5">
          <Section title="Assessment" hint={`Generated by the ${String(ai.source ?? "deterministic")} analyst`}>
            <div className="space-y-3">
              {ai.intent ? (
                <p className="text-xs font-medium text-ink">{String(ai.intent)}</p>
              ) : null}
              <p className="max-w-3xl text-sm leading-relaxed text-muted">
                {String(ai.narrative ?? ai.summary ?? "No analysis available.")}
              </p>
            </div>
          </Section>

          <Section title="Why the pipeline flagged this" hint="Every signal that contributed">
            <div className="space-y-4">
              <div className="flex flex-wrap gap-1.5">
                {((det.triggered_engines ?? []) as string[]).map((engine) => (
                  <span
                    key={engine}
                    className="rounded border border-rule bg-raised px-1.5 py-0.5 text-[10px] text-muted"
                  >
                    {engine.replaceAll("_", " ")}
                  </span>
                ))}
              </div>
              <ul className="space-y-1.5">
                {((det.reasoning ?? []) as string[]).map((reason, i) => (
                  <li key={i} className="flex items-start gap-2 text-[11px] leading-relaxed text-muted">
                    <span className={`mt-1.5 h-1 w-1 shrink-0 rounded-full ${tone.mark}`} aria-hidden />
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          </Section>

          {/* ATT&CK */}
          {attack?.primary?.technique_id ? (
            <Section title="MITRE ATT&CK" hint="The industry-standard name for this behaviour">
              <div className="space-y-4">
                <div className="space-y-1.5">
                  <a
                    href={attack.primary.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="mono inline-flex items-center gap-1.5 text-sm font-semibold text-accent transition hover:underline"
                  >
                    {attack.primary.technique_id}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                  <p className="text-xs font-medium text-ink">{attack.primary.technique_name}</p>
                  <p className="text-[11px] text-muted">Tactic: {attack.primary.tactic_name}</p>
                </div>

                <div className="space-y-2">
                  <p className="eyebrow">
                    Stage {attack.kill_chain_order} of {ATTACK_TACTICS.length} —{" "}
                    {attack.kill_chain_stage}
                  </p>
                  <KillChainMeter
                    reachedOrders={[attack.kill_chain_order ?? 0]}
                    furthestOrder={attack.kill_chain_order ?? 0}
                    showLabels
                  />
                </div>

                {(attack.techniques ?? []).length > 1 ? (
                  <div className="space-y-2 border-t border-rule-soft pt-3">
                    <p className="eyebrow">Corroborating techniques</p>
                    <ul className="space-y-1.5">
                      {(attack.techniques ?? [])
                        .filter((t) => t.technique_id !== attack.primary?.technique_id)
                        .map((t) => (
                          <li key={t.technique_id} className="flex items-baseline gap-2 text-[11px]">
                            <a
                              href={t.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="mono shrink-0 text-accent hover:underline"
                            >
                              {t.technique_id}
                            </a>
                            <span className="text-muted">{t.technique_name}</span>
                            <span className="ml-auto shrink-0 text-faint">{t.tactic_name}</span>
                          </li>
                        ))}
                    </ul>
                  </div>
                ) : null}
              </div>
            </Section>
          ) : null}

          {/* CIS control — the audit evidence */}
          <Section
            title="Control mapping"
            hint={
              cis.match_type === "catalog_retrieval"
                ? "Matched against the shipped benchmark catalog"
                : "Selected from the threat-class control mapping"
            }
          >
            {cis.benchmark_id ? (
              <div className="space-y-3.5">
                <PlainEnglish>
                  Banks are audited against security control frameworks. This is the
                  specific control the activity relates to — generated now, not
                  reconstructed for an auditor months later.
                </PlainEnglish>

                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="mono text-sm font-semibold text-accent">
                    {String(cis.benchmark_id)}
                  </span>
                  <span className="text-xs font-medium text-ink">{String(cis.title ?? "")}</span>
                  {cis.framework ? (
                    <span className="rounded border border-rule bg-raised px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-muted">
                      {String(cis.framework)}
                    </span>
                  ) : null}
                </div>

                {cis.description ? (
                  <Field label="What the control requires" body={String(cis.description)} />
                ) : null}
                {cis.rationale ? <Field label="Why it applies" body={String(cis.rationale)} /> : null}
                {cis.remediation ? (
                  <div className="space-y-1 border-l-2 border-accent-deep pl-3">
                    <p className="eyebrow">Remediation</p>
                    <p className="whitespace-pre-line text-xs leading-relaxed text-ink">
                      {String(cis.remediation).trim()}
                    </p>
                  </div>
                ) : null}
                {cis.audit_procedure ? (
                  <details className="rounded border border-rule bg-sunk/40">
                    <summary className="eyebrow cursor-pointer list-none px-3 py-2 transition hover:text-ink">
                      Audit procedure
                    </summary>
                    <pre className="mono scroll-x border-t border-rule-soft px-3 py-3 text-[10px] leading-relaxed text-muted">
                      {String(cis.audit_procedure).trim()}
                    </pre>
                  </details>
                ) : null}
              </div>
            ) : (
              <p className="text-xs text-faint">No control mapping produced for this incident.</p>
            )}
          </Section>

          {/* Raw evidence, last — available but not in the way */}
          <details className="overflow-hidden rounded-md border border-rule bg-surface">
            <summary className="eyebrow cursor-pointer list-none px-4 py-2.5 transition hover:text-ink">
              Raw log record
            </summary>
            <pre className="mono scroll-x max-h-72 overflow-y-auto border-t border-rule-soft px-4 py-3 text-[10px] leading-relaxed text-muted">
              {JSON.stringify(raw, null, 2)}
            </pre>
          </details>
        </div>

        {/* ── Right: what to do about it ───────────────────────────────────── */}
        <div className="space-y-5">
          {/* Notification clock, if this alert stands alone */}
          {incident.notification?.reportable ? (
            <Section title="Regulatory notification" hint="This looks reportable">
              <div className="space-y-4">
                <PlainEnglish>
                  A bank has to tell its regulator about a serious incident within hours.
                  The clock started when the pipeline reached its verdict.
                </PlainEnglish>
                <div className="space-y-3.5">
                  {incident.notification.clocks.map((clock) => (
                    <ClockRow key={clock.regime_id} clock={clock} />
                  ))}
                </div>
                <p className="text-[10px] leading-relaxed text-faint">
                  {incident.notification.disclaimer}
                </p>
              </div>
            </Section>
          ) : null}

          <ContainmentPanel plan={plan} response={resp} incidentId={incident.event_id} />

          {/* CVSS */}
          <Section title="Severity score" hint="CVSS 3.1, computed from the published equations">
            <div className="space-y-3">
              <PlainEnglish>
                A standard 0–10 severity score used across the industry. It is calculated
                by formula, not estimated — anyone can re-derive it from the vector below.
              </PlainEnglish>
              <div className="flex items-baseline gap-3">
                <span className="figure text-3xl font-semibold leading-none text-ink">
                  {String(cvss.base_score ?? "—")}
                </span>
                <SeverityChip value={cvss.severity} />
              </div>
              {cvss.vector_string ? (
                <p className="mono scroll-x rounded border border-rule bg-sunk px-2 py-1.5 text-[10px] text-muted">
                  {String(cvss.vector_string)}
                </p>
              ) : null}
            </div>
          </Section>

          <FeedbackPanel incidentId={incident.event_id} />
        </div>
      </div>
    </div>
  );
}

/* ─── Pieces ───────────────────────────────────────────────────────────────── */

function BackLink() {
  return (
    <Link
      href="/dashboard"
      className="inline-flex items-center gap-1.5 text-[11px] text-muted transition hover:text-ink"
    >
      <ArrowLeft className="h-3 w-3" />
      Back to queue
    </Link>
  );
}

function Field({ label, body }: { label: string; body: string }) {
  if (!body.trim()) return null;
  return (
    <div className="space-y-1">
      <p className="eyebrow">{label}</p>
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
      <Section title="Containment">
        <p className="text-xs text-faint">No containment actions recommended.</p>
      </Section>
    );
  }

  const auto = plan.filter((s) => s.execution === "auto");
  const gated = plan.filter((s) => s.execution === "requires_approval");

  return (
    <Section
      title="Containment plan"
      hint={`${auto.length} automatic · ${gated.length} need a human`}
    >
      <div className="space-y-4">
        <PlainEnglish>
          Some fixes are safe to apply automatically. Others could take a live banking
          service offline — which would be a worse outage than the attack — so a person
          decides those. The split is by how much damage the fix itself could do, not by
          how bad the attack is.
        </PlainEnglish>

        {auto.length > 0 ? (
          <div className="space-y-2">
            <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-sev-benign">
              <Zap className="h-3 w-3" />
              Applied automatically
            </p>
            <ul className="space-y-1.5">
              {auto.map((step) => (
                <li
                  key={step.action}
                  className="flex items-start gap-2.5 rounded border border-sev-benign/25 bg-sev-benign/8 px-3 py-2"
                >
                  <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sev-benign" />
                  <div className="min-w-0 space-y-0.5">
                    <p className="text-xs text-ink">{step.action}</p>
                    <p className="text-[10px] leading-relaxed text-muted">{step.rationale}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {gated.length > 0 ? (
          <div className="space-y-2">
            <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-sev-high">
              <TriangleAlert className="h-3 w-3" />
              Waiting on you
            </p>
            <ul className="space-y-2">
              {gated.map((step) => {
                const index = plan.indexOf(step);
                const state = states[index] ?? "idle";
                return (
                  <li
                    key={step.action}
                    className="space-y-2 rounded border border-sev-high/25 bg-sev-high/8 px-3 py-2.5"
                  >
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-baseline gap-2">
                        <p className="text-xs font-medium text-ink">{step.action}</p>
                        <span className="rounded border border-sev-high/35 bg-sev-high/12 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-sev-high">
                          {step.blast_radius}
                        </span>
                      </div>
                      <p className="text-[10px] leading-relaxed text-muted">{step.rationale}</p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      {state === "idle" ? (
                        <button
                          onClick={() => request(index, step.action)}
                          className="rounded border border-rule bg-raised px-2.5 py-1 text-[10px] font-semibold text-ink transition hover:border-accent-deep"
                        >
                          Submit for approval
                        </button>
                      ) : null}
                      {state === "submitting" ? (
                        <span className="flex items-center gap-1.5 text-[10px] text-muted">
                          <Loader2 className="h-3 w-3 animate-spin" /> Working…
                        </span>
                      ) : null}
                      {state === "pending" ? (
                        <>
                          <span className="text-[10px] text-sev-high">Queued —</span>
                          <button
                            onClick={() => decide(index, "approve")}
                            className="inline-flex items-center gap-1 rounded border border-sev-benign/40 bg-sev-benign/12 px-2.5 py-1 text-[10px] font-semibold text-sev-benign transition hover:bg-sev-benign/20"
                          >
                            <Check className="h-3 w-3" /> Approve
                          </button>
                          <button
                            onClick={() => decide(index, "reject")}
                            className="inline-flex items-center gap-1 rounded border border-sev-critical/40 bg-sev-critical/12 px-2.5 py-1 text-[10px] font-semibold text-sev-critical transition hover:bg-sev-critical/20"
                          >
                            <X className="h-3 w-3" /> Reject
                          </button>
                        </>
                      ) : null}
                      {state === "approved" ? (
                        <span className="flex items-center gap-1.5 text-[10px] font-semibold text-sev-benign">
                          <Check className="h-3 w-3" /> Approved — cleared to execute
                        </span>
                      ) : null}
                      {state === "rejected" ? (
                        <span className="flex items-center gap-1.5 text-[10px] font-semibold text-sev-critical">
                          <X className="h-3 w-3" /> Rejected — will not execute
                        </span>
                      ) : null}
                      {state === "error" ? (
                        <span className="text-[10px] text-sev-critical">
                          Backend unreachable. Start it and retry.
                        </span>
                      ) : null}
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        ) : null}

        {(response.recommended_actions as string[] | undefined)?.length ? (
          <div className="space-y-1.5 border-t border-rule-soft pt-3">
            <p className="eyebrow">Investigation steps</p>
            <ul className="space-y-1">
              {(response.recommended_actions as string[]).map((a) => (
                <li key={a} className="text-[11px] leading-relaxed text-muted">
                  · {a}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
    </Section>
  );
}

const FEEDBACK_REASONS = [
  { value: "known_good_ip", label: "Known good source" },
  { value: "authorized_scan", label: "Authorised security scan" },
  { value: "test_activity", label: "Test or lab activity" },
  { value: "maintenance_window", label: "Scheduled maintenance" },
  { value: "expected_behavior", label: "Expected behaviour" },
];

function FeedbackPanel({ incidentId }: { incidentId: string }) {
  const [reason, setReason] = useState(FEEDBACK_REASONS[1].value);
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
      setMessage(e instanceof Error ? e.message : "Could not record feedback.");
      setState("error");
    }
  };

  return (
    <Section title="Analyst decision" hint="Marking a false positive stops it recurring">
      <div className="space-y-3">
        <PlainEnglish>
          If this alert was wrong, saying so here creates a rule that stops the same
          pattern being raised again. That is how the system gets quieter over time
          instead of noisier.
        </PlainEnglish>

        {state === "done" ? (
          <p className="rounded border border-sev-benign/30 bg-sev-benign/10 px-3 py-2 text-[11px] leading-relaxed text-ink">
            {message}
          </p>
        ) : (
          <>
            <label className="block space-y-1.5">
              <span className="eyebrow">Reason</span>
              <select
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                className="w-full rounded border border-rule bg-sunk px-2 py-1.5 text-[11px] text-ink outline-none transition focus:border-accent-deep"
              >
                {FEEDBACK_REASONS.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </select>
            </label>

            <div className="flex gap-2">
              <button
                disabled={state === "sending"}
                onClick={() => send("true_positive")}
                className="flex-1 rounded border border-rule bg-raised px-3 py-2 text-[11px] font-semibold text-ink transition hover:border-accent-deep disabled:opacity-50"
              >
                Confirm real
              </button>
              <button
                disabled={state === "sending"}
                onClick={() => send("false_positive")}
                className="flex-1 rounded border border-sev-benign/40 bg-sev-benign/12 px-3 py-2 text-[11px] font-semibold text-sev-benign transition hover:bg-sev-benign/20 disabled:opacity-50"
              >
                False positive
              </button>
            </div>

            {state === "error" ? (
              <p className="text-[10px] text-sev-critical">{message}</p>
            ) : null}
          </>
        )}
      </div>
    </Section>
  );
}

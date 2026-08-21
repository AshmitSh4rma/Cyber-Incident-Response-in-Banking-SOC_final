"use client";

import { useState } from "react";
import { Check, Loader2, ShieldCheck, TriangleAlert, X, Zap } from "lucide-react";
import { EventPipeline } from "@/lib/mockData";

type StepState = "idle" | "submitting" | "pending" | "approved" | "rejected" | "error";

/**
 * The Layer 6 containment plan, split by whether an action can execute on its own.
 *
 * The distinction is the point: in a bank, isolating the host that clears card
 * transactions can cause a worse outage than the intrusion. So the gate is on
 * blast radius, not severity — and the reason for each decision is shown, because
 * an analyst asked to approve something needs to know why they were asked.
 */
export default function ContainmentPlan({
  pipeline,
  incidentId,
}: {
  pipeline: EventPipeline | null;
  incidentId: string;
}) {
  const plan = pipeline?.response?.containment_plan ?? [];
  const [states, setStates] = useState<Record<number, StepState>>({});
  const [approvalIds, setApprovalIds] = useState<Record<number, number>>({});

  if (plan.length === 0) {
    const legacy = pipeline?.response?.containment_steps ?? [];
    if (legacy.length === 0) {
      return (
        <div className="rounded border border-slate-800 bg-slate-900/60 p-5">
          <p className="eyebrow mb-2">Containment</p>
          <p className="text-xs text-slate-500">No containment actions recommended.</p>
        </div>
      );
    }
    return (
      <div className="rounded border border-slate-800 bg-slate-900/60 p-5">
        <p className="eyebrow mb-3">Containment</p>
        <ul className="space-y-1.5">
          {legacy.map((s) => (
            <li key={s} className="text-xs text-slate-300">
              • {s}
            </li>
          ))}
        </ul>
      </div>
    );
  }

  const auto = plan.filter((s) => s.execution === "auto");
  const gated = plan.filter((s) => s.execution === "requires_approval");

  async function requestApproval(index: number, action: string) {
    setStates((p) => ({ ...p, [index]: "submitting" }));
    try {
      const res = await fetch(`/api/incidents/${incidentId}/approvals`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.message ?? `Request failed (${res.status})`);
      setApprovalIds((p) => ({ ...p, [index]: data.approval_id }));
      setStates((p) => ({ ...p, [index]: "pending" }));
    } catch {
      setStates((p) => ({ ...p, [index]: "error" }));
    }
  }

  async function decide(index: number, decision: "approve" | "reject") {
    const approvalId = approvalIds[index];
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
  }

  return (
    <div className="space-y-4 rounded border border-slate-800 bg-slate-900/60 p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="eyebrow">Containment plan</p>
        <p className="text-[10px] text-slate-500">
          <span className="tabular font-semibold text-emerald-400">{auto.length}</span> automatic ·{" "}
          <span className="tabular font-semibold text-amber-400">{gated.length}</span> need approval
        </p>
      </div>

      {/* Auto-executable */}
      {auto.length > 0 && (
        <div className="space-y-2">
          <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-400">
            <Zap className="h-3 w-3" />
            Safe to automate
          </p>
          <ul className="space-y-1.5">
            {auto.map((step) => (
              <li
                key={step.action}
                className="flex items-start gap-2.5 rounded border border-emerald-900/40 bg-emerald-950/15 px-3 py-2"
              >
                <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                <div className="min-w-0 space-y-0.5">
                  <p className="text-xs text-slate-200">{step.action}</p>
                  <p className="text-[10px] text-slate-500">{step.rationale}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Requires a human */}
      {gated.length > 0 && (
        <div className="space-y-2">
          <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-amber-400">
            <TriangleAlert className="h-3 w-3" />
            Held for analyst approval
          </p>
          <ul className="space-y-2">
            {gated.map((step) => {
              const index = plan.indexOf(step);
              const state = states[index] ?? "idle";
              return (
                <li
                  key={step.action}
                  className="space-y-2 rounded border border-amber-900/40 bg-amber-950/12 px-3 py-2.5"
                >
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-baseline gap-2">
                      <p className="text-xs font-medium text-slate-100">{step.action}</p>
                      <span className="rounded border border-amber-800/50 bg-amber-950/40 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-amber-400">
                        {step.blast_radius}
                      </span>
                    </div>
                    <p className="text-[10px] leading-relaxed text-slate-400">{step.rationale}</p>
                  </div>

                  <div className="flex items-center gap-2">
                    {state === "idle" && (
                      <button
                        onClick={() => requestApproval(index, step.action)}
                        className="rounded border border-slate-600 bg-slate-800/60 px-2.5 py-1 text-[10px] font-semibold text-slate-200 transition hover:bg-slate-700"
                      >
                        Submit for approval
                      </button>
                    )}
                    {state === "submitting" && (
                      <span className="flex items-center gap-1.5 text-[10px] text-slate-400">
                        <Loader2 className="h-3 w-3 animate-spin" /> Working…
                      </span>
                    )}
                    {state === "pending" && (
                      <>
                        <span className="text-[10px] text-amber-400">Queued —</span>
                        <button
                          onClick={() => decide(index, "approve")}
                          className="inline-flex items-center gap-1 rounded border border-emerald-800/60 bg-emerald-950/40 px-2.5 py-1 text-[10px] font-semibold text-emerald-300 transition hover:bg-emerald-950/70"
                        >
                          <Check className="h-3 w-3" /> Approve
                        </button>
                        <button
                          onClick={() => decide(index, "reject")}
                          className="inline-flex items-center gap-1 rounded border border-red-800/60 bg-red-950/40 px-2.5 py-1 text-[10px] font-semibold text-red-300 transition hover:bg-red-950/70"
                        >
                          <X className="h-3 w-3" /> Reject
                        </button>
                      </>
                    )}
                    {state === "approved" && (
                      <span className="flex items-center gap-1.5 text-[10px] font-semibold text-emerald-400">
                        <Check className="h-3 w-3" /> Approved — cleared to execute
                      </span>
                    )}
                    {state === "rejected" && (
                      <span className="flex items-center gap-1.5 text-[10px] font-semibold text-red-400">
                        <X className="h-3 w-3" /> Rejected — will not execute
                      </span>
                    )}
                    {state === "error" && (
                      <span className="text-[10px] text-red-400">
                        Could not reach the backend. Start it and retry.
                      </span>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}

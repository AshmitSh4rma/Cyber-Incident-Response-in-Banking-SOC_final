"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Check,
  FlaskConical,
  RotateCcw,
  Save,
  Undo2,
  X,
} from "lucide-react";

import {
  Block,
  EmptyState,
  PlainEnglish,
  Reveal,
  Screen,
  Section,
  Skeleton,
} from "@/components/soc/primitives";
import { useDetail } from "@/lib/detail";
import { formatTimestamp } from "@/lib/severity";

/**
 * Settings.
 *
 * The screen exists because the alternative is a developer. Every number on this
 * page was a Python literal until it wasn't: how many failed logins count as an
 * attack, which regulators this institution answers to, how long its analysts
 * actually take, what a machine is allowed to do unattended. None of that is a
 * code change, and a system that pretends otherwise cannot be deployed twice.
 *
 * Four states are always answerable, because a settings screen that cannot
 * answer them is worse than no settings screen:
 *
 *   Current   — a band at the top says whether anything differs from the shipped
 *               defaults, names what, and says when it last changed.
 *   Success   — a save reports each change as "from → to", then says what to do
 *               next rather than leaving the operator to guess.
 *   Failure   — a rejected save says nothing was written, and marks every
 *               offending control with the reason. It never partially applies.
 *   Next      — "Preview the effect" runs the pipeline twice and shows the
 *               difference in numbers, before anything is kept.
 *
 * The schema comes from the backend, including labels, bounds, help text and the
 * per-setting "what this affects" line. Nothing on this page hardcodes a setting
 * name; adding one server-side makes it appear here.
 */

type Setting = {
  key: string;
  group: string;
  label: string;
  help: string | null;
  type: "int" | "float" | "bool" | "choice" | "multi";
  default: unknown;
  min: number | null;
  max: number | null;
  unit: string | null;
  options: [string, string][] | null;
  min_selected: number | null;
  affects: string;
  demo: unknown;
};

type Group = { id: string; label: string; help: string };

type Status = {
  groups: Group[];
  settings: Setting[];
  values: Record<string, unknown>;
  defaults: Record<string, unknown>;
  modified: string[];
  is_default: boolean;
  updated_at: string | null;
  updated_by: string | null;
  stored_file_readable: boolean;
  path: string;
  audit: { at: string; actor: string; changes: Change[] }[];
};

type Change = { key: string; label: string; from: unknown; to: unknown };

type Preview = {
  message: string;
  source: string;
  differences: { metric: string; before: unknown; after: unknown }[];
};

type Outcome =
  | { kind: "saved"; message: string; changes: Change[] }
  | { kind: "rejected"; message: string; errors: Record<string, string> }
  | { kind: "unreachable"; message: string };

/** Metric keys the preview returns, in plain words. */
const METRIC_LABELS: Record<string, string> = {
  alerts: "Alerts read",
  actionable: "Alerts needing attention",
  filtered_out: "Filtered out as normal",
  severity: "Severity spread",
  campaigns: "Attacks reconstructed",
  investigations: "Things to look at",
  reportable_campaigns: "Attacks that must be reported",
  notification_deadlines: "Regulator deadlines running",
  actions_automatic: "Actions taken automatically",
  actions_needing_approval: "Actions awaiting approval",
  hours_saved: "Analyst hours saved",
};

function sameValue(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((v, i) => v === b[i]);
  }
  return a === b;
}

function describe(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "on" : "off";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "none";
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${k} ${v}`)
      .join(" · ");
  }
  return String(value);
}

export default function SettingsPage() {
  const { isAnalyst } = useDetail();

  const [status, setStatus] = useState<Status | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  /** Edits not yet sent. Absent key = unchanged. */
  const [draft, setDraft] = useState<Record<string, unknown>>({});
  const [busy, setBusy] = useState<null | "saving" | "previewing" | "resetting">(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/config", { cache: "no-store" });
      if (!res.ok) throw new Error(`Settings service returned ${res.status}`);
      setStatus((await res.json()) as Status);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const pending = useMemo(() => {
    if (!status) return [] as string[];
    return Object.keys(draft).filter((k) => !sameValue(draft[k], status.values[k]));
  }, [draft, status]);

  const fieldErrors = outcome?.kind === "rejected" ? outcome.errors : {};

  /** Value shown in a control: the edit if there is one, else what is stored. */
  const shown = (key: string): unknown =>
    key in draft ? draft[key] : status?.values[key];

  const edit = (key: string, value: unknown) => {
    setDraft((prev) => ({ ...prev, [key]: value }));
    // A stale verdict about a value the operator has since changed is worse than
    // no verdict, so both clear on the next edit.
    setPreview(null);
    if (outcome) setOutcome(null);
  };

  const discard = () => {
    setDraft({});
    setPreview(null);
    setOutcome(null);
  };

  const patch = useMemo(
    () => Object.fromEntries(pending.map((k) => [k, draft[k]])),
    [pending, draft],
  );

  const send = async (
    url: string,
    method: "PUT" | "POST",
    body: unknown,
  ): Promise<{ ok: boolean; status: number; data: Record<string, unknown> }> => {
    const res = await fetch(url, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    return { ok: res.ok, status: res.status, data };
  };

  const save = async () => {
    setBusy("saving");
    setPreview(null);
    try {
      const { ok, status: code, data } = await send("/api/config", "PUT", { values: patch });
      if (code === 422) {
        setOutcome({
          kind: "rejected",
          message: String(data.message ?? "Nothing was saved."),
          errors: (data.errors ?? {}) as Record<string, string>,
        });
        return;
      }
      if (!ok) {
        setOutcome({ kind: "unreachable", message: String(data.message ?? `Save failed (${code}).`) });
        return;
      }
      setOutcome({
        kind: "saved",
        message: String(data.message ?? "Saved."),
        changes: (data.changes ?? []) as Change[],
      });
      setDraft({});
      setStatus(data as unknown as Status);
    } catch (err) {
      setOutcome({
        kind: "unreachable",
        message: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(null);
    }
  };

  const runPreview = async () => {
    setBusy("previewing");
    try {
      const { ok, status: code, data } = await send("/api/config/preview", "POST", { values: patch });
      if (code === 422) {
        setOutcome({
          kind: "rejected",
          message: String(data.message ?? "Cannot preview an invalid configuration."),
          errors: (data.errors ?? {}) as Record<string, string>,
        });
        setPreview(null);
        return;
      }
      if (!ok) {
        setOutcome({ kind: "unreachable", message: String(data.message ?? `Preview failed (${code}).`) });
        return;
      }
      setOutcome(null);
      setPreview(data as unknown as Preview);
    } catch (err) {
      setOutcome({ kind: "unreachable", message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(null);
    }
  };

  const resetAll = async () => {
    setBusy("resetting");
    setPreview(null);
    try {
      const { ok, data } = await send("/api/config/reset", "POST", {});
      if (!ok) {
        setOutcome({ kind: "unreachable", message: String(data.message ?? "Reset failed.") });
        return;
      }
      setOutcome({
        kind: "saved",
        message: String(data.message ?? "Reset to defaults."),
        changes: (data.changes ?? []) as Change[],
      });
      setDraft({});
      setStatus(data as unknown as Status);
    } finally {
      setBusy(null);
    }
  };

  /* ── Loading and failure ────────────────────────────────────────────────── */

  if (loadError) {
    return (
      <Screen className="max-w-3xl">
        <Block>
          <p className="eyebrow">Settings</p>
          <h1 className="mt-1.5 text-2xl font-semibold tracking-tight text-ink">
            How this system behaves
          </h1>
        </Block>
        <EmptyState
          icon={<AlertTriangle className="h-9 w-9" />}
          title="Could not load the settings"
          detail={`${loadError}. Start the backend with "uvicorn api_server:app --port 8000" and reload.`}
        />
      </Screen>
    );
  }

  if (!status) {
    return (
      <Screen>
        <Block><Skeleton className="h-20" /></Block>
        <Block><Skeleton className="h-64" /></Block>
      </Screen>
    );
  }

  const modifiedSet = new Set(status.modified);

  return (
    <Screen>
      {/* ── Lead ───────────────────────────────────────────────────────────── */}
      <Block>
        <p className="eyebrow">Settings</p>
        <h1 className="mt-1.5 text-2xl font-semibold tracking-tight text-ink">
          How this system behaves
        </h1>
        <PlainEnglish>
          Everything here changes what the system does, and none of it needs a developer
          or a restart. Change something and you can see what it would do to the numbers
          before you keep it.
        </PlainEnglish>
      </Block>

      {/* ── Current status ─────────────────────────────────────────────────── */}
      <Block>
        <div className="rounded-md border border-rule bg-surface">
          <div className="flex flex-wrap items-start justify-between gap-4 p-4">
            <div className="min-w-0 space-y-1.5">
              <p className="flex items-center gap-2 text-[13px] font-medium text-ink">
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    status.is_default ? "bg-sev-benign" : "bg-accent"
                  }`}
                  aria-hidden
                />
                {status.is_default
                  ? "Running on the shipped defaults"
                  : `${status.modified.length} setting${status.modified.length === 1 ? "" : "s"} changed from default`}
              </p>
              <p className="text-[11px] leading-relaxed text-muted">
                {status.is_default
                  ? "Nothing has been customised for this institution yet."
                  : status.updated_at
                    ? `Last changed by ${status.updated_by ?? "console"} on ${formatTimestamp(status.updated_at)}.`
                    : "Changed, but the timestamp is unavailable."}
              </p>
              {!status.is_default ? (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {status.modified.map((key) => {
                    const setting = status.settings.find((s) => s.key === key);
                    return (
                      <span
                        key={key}
                        className="rounded border border-accent-deep bg-accent/10 px-1.5 py-0.5 text-[10px] text-accent"
                      >
                        {setting?.label ?? key}
                      </span>
                    );
                  })}
                </div>
              ) : null}
            </div>

            <button
              onClick={resetAll}
              disabled={status.is_default || busy !== null}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-rule px-3 py-2 text-[11px] font-medium text-muted transition hover:bg-raised hover:text-ink disabled:opacity-40"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              {busy === "resetting" ? "Resetting…" : "Reset all to defaults"}
            </button>
          </div>

          {!status.stored_file_readable ? (
            <p className="flex items-start gap-2 border-t border-sev-high/30 bg-sev-high/10 px-4 py-2.5 text-[11px] leading-relaxed text-sev-high">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>
                <span className="font-semibold">{status.path} could not be read.</span>{" "}
                The system is running on defaults. Saving here will replace the unreadable file.
              </span>
            </p>
          ) : null}

          {isAnalyst ? (
            <p className="mono border-t border-rule-soft px-4 py-2 text-[10px] text-faint">
              stored in {status.path} — only values that differ from default are written
            </p>
          ) : null}
        </div>
      </Block>

      {/* ── Outcome of the last attempt ────────────────────────────────────── */}
      {outcome ? (
        <Block>
          {outcome.kind === "saved" ? (
            <div className="rise space-y-3 rounded-md border border-sev-benign/40 bg-sev-benign/8 p-4">
              <p className="flex items-center gap-2 text-[13px] font-semibold text-sev-benign">
                <Check className="h-4 w-4" />
                {outcome.message}
              </p>
              {outcome.changes.length ? (
                <ul className="space-y-1.5">
                  {outcome.changes.map((c) => (
                    <li key={c.key} className="flex flex-wrap items-baseline gap-x-2 text-[11px]">
                      <span className="text-muted">{c.label}</span>
                      <span className="tabular text-faint line-through">{describe(c.from)}</span>
                      <span className="text-faint">→</span>
                      <span className="tabular font-semibold text-ink">{describe(c.to)}</span>
                    </li>
                  ))}
                </ul>
              ) : null}
              <div className="border-t border-sev-benign/25 pt-2.5">
                <p className="eyebrow mb-1.5">What now</p>
                <ul className="space-y-1 text-[11px] leading-relaxed text-muted">
                  <li>
                    · New activity is scored with these settings from now on — nothing to restart.
                  </li>
                  <li>
                    · Alerts already in the queue keep their old scores. Replay a scenario from{" "}
                    <span className="font-medium text-ink">Simulation</span> to re-score them.
                  </li>
                </ul>
              </div>
            </div>
          ) : outcome.kind === "rejected" ? (
            <div className="rise space-y-2 rounded-md border border-sev-critical/40 bg-sev-critical/10 p-4">
              <p className="flex items-center gap-2 text-[13px] font-semibold text-sev-critical">
                <X className="h-4 w-4" />
                {outcome.message}
              </p>
              <p className="text-[11px] leading-relaxed text-muted">
                Your edits are still here. Fix the {Object.keys(outcome.errors).length} marked
                below and save again — a configuration is applied whole or not at all, so
                nothing was written.
              </p>
            </div>
          ) : (
            <div className="rise space-y-2 rounded-md border border-sev-high/40 bg-sev-high/10 p-4">
              <p className="flex items-center gap-2 text-[13px] font-semibold text-sev-high">
                <AlertTriangle className="h-4 w-4" />
                Could not reach the settings service
              </p>
              <p className="text-[11px] leading-relaxed text-muted">
                {outcome.message}. Nothing was changed. Your edits are still here — try again
                once the backend is up.
              </p>
            </div>
          )}
        </Block>
      ) : null}

      {/* ── Preview ────────────────────────────────────────────────────────── */}
      {preview ? (
        <Block>
          <div className="rise rounded-md border border-accent-deep bg-accent/8">
            <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-accent-deep/40 px-4 py-3">
              <p className="flex items-center gap-2 text-[13px] font-semibold text-accent">
                <FlaskConical className="h-4 w-4" />
                {preview.message}
              </p>
              <p className="text-[10px] text-faint">
                Not saved · measured on {preview.source}
              </p>
            </div>

            {preview.differences.length ? (
              <div className="scroll-x">
                <table className="w-full min-w-[440px] text-left text-[11px]">
                  <thead>
                    <tr className="border-b border-rule-soft">
                      {["", "Now", "Would become"].map((h, i) => (
                        <th key={h + i} className="eyebrow px-4 py-2">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {preview.differences.map((d) => (
                      <tr key={d.metric} className="border-b border-rule-soft last:border-0">
                        <td className="px-4 py-2 text-muted">
                          {METRIC_LABELS[d.metric] ?? d.metric.replaceAll("_", " ")}
                        </td>
                        <td className="tabular px-4 py-2 text-faint">{describe(d.before)}</td>
                        <td className="tabular px-4 py-2 font-semibold text-ink">
                          {describe(d.after)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="px-4 py-3 text-[11px] leading-relaxed text-muted">
                The change is valid, it simply does not move any of these figures on the demo
                records. That is a real answer, not a failure — a threshold can be well clear
                of everything in the current data.
              </p>
            )}
          </div>
        </Block>
      ) : null}

      {/* ── Pending edits ──────────────────────────────────────────────────── */}
      {pending.length ? (
        <Block>
          <div className="rise sticky top-2 z-20 flex flex-wrap items-center justify-between gap-3 rounded-md border border-accent-deep bg-raised/95 px-4 py-3 backdrop-blur">
            <p className="text-[12px] font-medium text-ink">
              {pending.length} unsaved change{pending.length === 1 ? "" : "s"}
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={discard}
                disabled={busy !== null}
                className="inline-flex items-center gap-1.5 rounded-md border border-rule px-3 py-2 text-[11px] font-medium text-muted transition hover:bg-surface hover:text-ink disabled:opacity-40"
              >
                <Undo2 className="h-3.5 w-3.5" />
                Discard
              </button>
              <button
                onClick={runPreview}
                disabled={busy !== null}
                className="inline-flex items-center gap-1.5 rounded-md border border-accent-deep px-3 py-2 text-[11px] font-semibold text-accent transition hover:bg-accent/15 disabled:opacity-40"
              >
                <FlaskConical className="h-3.5 w-3.5" />
                {busy === "previewing" ? "Working it out…" : "Preview the effect"}
              </button>
              <button
                onClick={save}
                disabled={busy !== null}
                className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-2 text-[11px] font-semibold text-ground transition hover:opacity-90 disabled:opacity-40"
              >
                <Save className="h-3.5 w-3.5" />
                {busy === "saving" ? "Saving…" : "Save and apply"}
              </button>
            </div>
          </div>
        </Block>
      ) : null}

      {/* ── The settings themselves ────────────────────────────────────────── */}
      {status.groups.map((group) => {
        const settings = status.settings.filter((s) => s.group === group.id);
        if (!settings.length) return null;
        return (
          <Section key={group.id} title={group.label} hint={group.help}>
            <div className="divide-y divide-rule-soft">
              {settings.map((setting) => (
                <SettingRow
                  key={setting.key}
                  setting={setting}
                  value={shown(setting.key)}
                  isDirty={pending.includes(setting.key)}
                  isModified={modifiedSet.has(setting.key)}
                  error={fieldErrors[setting.key]}
                  showDetail={isAnalyst}
                  onChange={(v) => edit(setting.key, v)}
                  onRevert={() => edit(setting.key, setting.default)}
                />
              ))}
            </div>
          </Section>
        );
      })}

      {/* ── History ────────────────────────────────────────────────────────── */}
      {status.audit.length ? (
        <Block>
          <Reveal label="Show recent changes" count={status.audit.length}>
            <ul className="space-y-3">
              {status.audit.map((entry, i) => (
                <li key={`${entry.at}-${i}`} className="space-y-1">
                  <p className="text-[10px] text-faint">
                    {formatTimestamp(entry.at)} · {entry.actor}
                  </p>
                  <ul className="space-y-0.5">
                    {entry.changes.map((c) => (
                      <li key={c.key} className="flex flex-wrap items-baseline gap-x-2 text-[11px]">
                        <span className="text-muted">{c.label}</span>
                        <span className="tabular text-faint">{describe(c.from)}</span>
                        <span className="text-faint">→</span>
                        <span className="tabular text-ink">{describe(c.to)}</span>
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          </Reveal>
        </Block>
      ) : null}
    </Screen>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   One setting
   ═══════════════════════════════════════════════════════════════════════════ */

function SettingRow({
  setting,
  value,
  isDirty,
  isModified,
  error,
  showDetail,
  onChange,
  onRevert,
}: {
  setting: Setting;
  value: unknown;
  isDirty: boolean;
  isModified: boolean;
  error?: string;
  showDetail: boolean;
  onChange: (value: unknown) => void;
  onRevert: () => void;
}) {
  const atDefault = sameValue(value, setting.default);
  const errorId = error ? `${setting.key}-error` : undefined;

  return (
    <div className={`px-4 py-3.5 transition-colors ${isDirty ? "bg-accent/5" : ""}`}>
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-2">
        <div className="min-w-[15rem] flex-1 space-y-1">
          <label htmlFor={setting.key} className="block text-[12px] font-medium text-ink">
            {setting.label}
            {isDirty ? (
              <span className="ml-2 rounded border border-accent-deep bg-accent/10 px-1 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-accent">
                unsaved
              </span>
            ) : isModified ? (
              <span className="ml-2 text-[9px] font-semibold uppercase tracking-wider text-faint">
                customised
              </span>
            ) : null}
          </label>
          {setting.help ? (
            <p className="max-w-prose text-[11px] leading-relaxed text-muted">{setting.help}</p>
          ) : null}
        </div>

        <div className="w-full max-w-sm shrink-0 space-y-1.5">
          <Control setting={setting} value={value} onChange={onChange} errorId={errorId} />

          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-[10px] text-faint">
              {atDefault ? (
                "Default"
              ) : (
                <>
                  Default: <span className="tabular">{describe(setting.default)}</span>
                </>
              )}
            </p>
            <div className="flex items-center gap-2">
              {setting.demo !== null && setting.demo !== undefined
                && !sameValue(setting.demo, value) ? (
                <button
                  onClick={() => onChange(setting.demo)}
                  className="text-[10px] font-medium text-accent transition hover:underline"
                  title="Set a value that visibly changes the result, for a demonstration"
                >
                  try {describe(setting.demo)}
                </button>
              ) : null}
              {!atDefault ? (
                <button
                  onClick={onRevert}
                  className="text-[10px] text-faint transition hover:text-ink"
                >
                  reset
                </button>
              ) : null}
            </div>
          </div>
        </div>
      </div>

      {error ? (
        <p
          id={errorId}
          role="alert"
          className="mt-2.5 flex items-start gap-2 rounded border border-sev-critical/40 bg-sev-critical/10 px-2.5 py-2 text-[11px] leading-relaxed text-sev-critical"
        >
          <X className="mt-0.5 h-3 w-3 shrink-0" />
          {error}
        </p>
      ) : null}

      {/* "What this affects" is the consequence, not the description — it matters
          at the moment someone moves the control and almost never otherwise. So
          it appears when the row is dirty rather than sitting behind twenty-two
          identical disclosure buttons. Analysts, who are reading rather than
          demonstrating, get it permanently. */}
      {isDirty || showDetail ? (
        <p className="rise mt-2.5 flex items-start gap-2 border-t border-rule-soft pt-2 text-[10.5px] leading-relaxed text-muted">
          <span className="mt-1 h-1 w-1 shrink-0 rounded-full bg-accent" aria-hidden />
          <span>
            {showDetail ? <span className="mono text-faint">{setting.key} — </span> : null}
            {setting.affects}
          </span>
        </p>
      ) : null}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   Controls, chosen by declared type
   ═══════════════════════════════════════════════════════════════════════════ */

function Control({
  setting,
  value,
  onChange,
  errorId,
}: {
  setting: Setting;
  value: unknown;
  onChange: (value: unknown) => void;
  errorId?: string;
}) {
  const invalid = errorId ? true : undefined;

  if (setting.type === "bool") {
    const on = value === true;
    return (
      <button
        id={setting.key}
        role="switch"
        aria-checked={on}
        aria-invalid={invalid}
        aria-describedby={errorId}
        onClick={() => onChange(!on)}
        className={`flex w-full items-center justify-between rounded-md border px-3 py-2 text-[11px] font-medium transition ${
          on
            ? "border-accent-deep bg-accent/12 text-accent"
            : "border-rule bg-sunk text-muted hover:text-ink"
        }`}
      >
        {on ? "On" : "Off"}
        <span
          className={`relative h-4 w-7 rounded-full transition-colors ${
            on ? "bg-accent" : "bg-rule"
          }`}
        >
          <span
            className={`absolute top-0.5 h-3 w-3 rounded-full bg-ground transition-all ${
              on ? "left-3.5" : "left-0.5"
            }`}
          />
        </span>
      </button>
    );
  }

  if (setting.type === "choice") {
    const options = setting.options ?? [];
    // Short option sets read better as buttons — the whole range is visible at
    // once, which is the point on a screen someone is comparing values on.
    const asButtons = options.length <= 4 && options.every(([, l]) => l.length <= 14);
    if (asButtons) {
      return (
        <div
          id={setting.key}
          role="radiogroup"
          aria-invalid={invalid}
          aria-describedby={errorId}
          className="flex rounded-md border border-rule bg-sunk p-0.5"
        >
          {options.map(([optionValue, label]) => {
            const active = value === optionValue;
            return (
              <button
                key={optionValue}
                role="radio"
                aria-checked={active}
                onClick={() => onChange(optionValue)}
                className={`flex-1 rounded px-2 py-1.5 text-[10px] font-semibold uppercase tracking-wider transition ${
                  active ? "bg-raised text-ink" : "text-faint hover:text-muted"
                }`}
              >
                {label}
              </button>
            );
          })}
        </div>
      );
    }
    return (
      <select
        id={setting.key}
        value={String(value ?? "")}
        aria-invalid={invalid}
        aria-describedby={errorId}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-md border border-rule bg-sunk px-2.5 py-2 text-[11px] text-ink outline-none transition focus:border-accent-deep"
      >
        {options.map(([optionValue, label]) => (
          <option key={optionValue} value={optionValue}>
            {label}
          </option>
        ))}
      </select>
    );
  }

  if (setting.type === "multi") {
    const chosen = Array.isArray(value) ? (value as string[]) : [];
    const floor = setting.min_selected ?? 0;
    return (
      <div id={setting.key} role="group" aria-describedby={errorId} className="space-y-1">
        {(setting.options ?? []).map(([optionValue, label]) => {
          const on = chosen.includes(optionValue);
          const lastOne = on && chosen.length <= floor;
          return (
            <label
              key={optionValue}
              className={`flex cursor-pointer items-start gap-2.5 rounded border px-2.5 py-2 text-[11px] leading-relaxed transition ${
                on ? "border-accent-deep bg-accent/8 text-ink" : "border-rule bg-sunk text-muted hover:text-ink"
              } ${lastOne ? "cursor-not-allowed opacity-70" : ""}`}
              title={lastOne ? `At least ${floor} must stay selected` : undefined}
            >
              <input
                type="checkbox"
                checked={on}
                disabled={lastOne}
                onChange={() =>
                  onChange(
                    on
                      ? chosen.filter((v) => v !== optionValue)
                      : [...chosen, optionValue],
                  )
                }
                className="mt-0.5 h-3 w-3 shrink-0 accent-[var(--accent)]"
              />
              <span>{label}</span>
            </label>
          );
        })}
      </div>
    );
  }

  // int / float — a slider, because a threshold is a position in a range and a
  // bare number box hides both the bounds and how far from them you are.
  const min = setting.min ?? 0;
  const max = setting.max ?? 100;
  const step = setting.type === "int" ? 1 : Math.max(0.01, Number(((max - min) / 200).toFixed(2)));
  const current = typeof value === "number" ? value : Number(value ?? min);

  return (
    <div className="space-y-1">
      <div className="flex items-baseline justify-between gap-3">
        <input
          id={setting.key}
          type="range"
          min={min}
          max={max}
          step={step}
          value={Number.isFinite(current) ? current : min}
          aria-invalid={invalid}
          aria-describedby={errorId}
          onChange={(e) =>
            onChange(setting.type === "int" ? Number.parseInt(e.target.value, 10) : Number(e.target.value))
          }
          className="h-1 flex-1 cursor-pointer appearance-none rounded-full bg-track-neutral accent-[var(--accent)]"
        />
        <span className="figure w-24 shrink-0 text-right text-[13px] font-semibold text-ink">
          {Number.isFinite(current) ? current : "—"}
          {setting.unit ? (
            <span className="ml-1 text-[10px] font-normal text-faint">{setting.unit}</span>
          ) : null}
        </span>
      </div>
      <div className="flex justify-between text-[9px] text-faint">
        <span className="tabular">{min}</span>
        <span className="tabular">{max}</span>
      </div>
    </div>
  );
}

"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, CheckCircle2, ChevronRight, Loader2, Terminal, Upload } from "lucide-react";

import {
  Block,
  PlainEnglish,
  Reveal,
  Screen,
  Section,
} from "@/components/soc/primitives";
import { useDetail } from "@/lib/detail";
import { EASE_OUT, useCountUp, usePrefersReducedMotion } from "@/lib/motion";
import { formatBytes } from "@/lib/severity";

/**
 * Scenario replay.
 *
 * Every scenario here produces nothing but RAW LOG RECORDS, which are posted to
 * POST /run-pipeline exactly as an uploaded log file would be. The verdict,
 * severity, control mapping, CVSS score and campaign grouping are all decided by
 * the Python pipeline.
 *
 * This page used to carry a pre-built incident for every scenario — detection,
 * CIS, CVSS, response, the lot — and throw all of it away except `raw_event`,
 * because the backend recomputes it. Worse, it kept those fabrications as an
 * offline fallback, so with the backend down the dashboard filled with
 * convincing fake incidents. Both are gone: nothing on this page decides
 * anything about a threat.
 */

// ─── Raw log helpers ─────────────────────────────────────────────────────────

const randInt = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;
const externalIp = (prefix: string) => `${prefix}.${randInt(1, 254)}.${randInt(1, 254)}`;
const at = (offsetMs: number) => new Date(Date.now() - 3_600_000 + offsetMs).toISOString();

type RawLog = Record<string, string | number | null | undefined>;

type Scenario = {
  id: string;
  label: string;
  technique: string;
  summary: string;
  /** What the pipeline should conclude — shown so you can check it did. */
  expect: string;
  generate: () => RawLog[];
};

const SCENARIOS: Scenario[] = [
  {
    id: "port_scan",
    label: "Port scan",
    technique: "T1595.001",
    summary: "Sequential probing of exposed services before exploitation.",
    expect: "Reconnaissance · medium",
    generate: () => {
      const src = externalIp("198.51");
      return [22, 80, 443, 3306, 8080, 3389].map((port, i) => ({
        timestamp: at(i * 4_000),
        log_type: "network",
        source_ip: src,
        destination_ip: "10.20.0.11",
        port,
        protocol: "tcp",
        action: "port_scan",
        affected_host: "dmz-web-01",
        bytes_in: 64,
        bytes_out: 0,
      }));
    },
  },
  {
    id: "brute_force",
    label: "SSH brute force",
    technique: "T1110.001",
    summary: "Repeated failed authentication against an exposed bastion host.",
    expect: "Credential Access · high",
    generate: () => {
      const src = externalIp("45.128");
      return ["root", "admin", "oracle", "deploy", "jenkins", "postgres", "backup"].map(
        (user, i) => ({
          timestamp: at(i * 9_000),
          log_type: "auth",
          source_ip: src,
          destination_ip: "10.10.1.4",
          port: 22,
          protocol: "tcp",
          action: "failed_login",
          affected_host: "ssh-bastion-01",
          affected_user: user,
          result: "failure",
        }),
      );
    },
  },
  {
    id: "sql_injection",
    label: "SQL injection",
    technique: "T1190",
    summary: "Authentication bypass payloads against the retail banking login.",
    expect: "Initial Access · high",
    generate: () => {
      const src = externalIp("91.240");
      return [
        "/retail/login?user=admin' OR '1'='1--",
        "/retail/accounts?id=1 UNION SELECT card_number,cvv FROM cards",
        "/retail/login?user=admin'--",
      ].map((url, i) => ({
        timestamp: at(i * 21_000),
        log_type: "web",
        source_ip: src,
        destination_ip: "10.20.0.11",
        url,
        http_method: "POST",
        http_status: 200,
        action: "web_attack",
        affected_host: "dmz-web-01",
        user_agent: "sqlmap/1.8#stable",
        response_size: randInt(4000, 24000),
      }));
    },
  },
  {
    id: "web_shell",
    label: "Web shell upload",
    technique: "T1505.003",
    summary: "Executable dropped into a writable web directory for persistence.",
    expect: "Persistence · high",
    generate: () => {
      const src = externalIp("185.199");
      return ["/admin/upload.php", "/uploads/shell.php?cmd=id"].map((url, i) => ({
        timestamp: at(i * 40_000),
        log_type: "web",
        source_ip: src,
        destination_ip: "10.20.0.11",
        url,
        http_method: i === 0 ? "POST" : "GET",
        http_status: i === 0 ? 201 : 200,
        action: "web_attack",
        affected_host: "dmz-web-01",
        user_agent: "python-requests/2.32",
        request_size: i === 0 ? 8814 : 190,
      }));
    },
  },
  {
    id: "c2_beaconing",
    label: "C2 beaconing",
    technique: "T1071.001",
    summary: "Regular-interval HTTPS callbacks to a known command-and-control host.",
    expect: "Command and Control · high",
    generate: () => {
      return Array.from({ length: 5 }, (_, i) => ({
        timestamp: at(i * 60_000),
        log_type: "network",
        source_ip: "10.20.0.11",
        destination_ip: "185.14.22.91",
        port: 443,
        protocol: "https",
        action: "beaconing",
        affected_host: "dmz-web-01",
        bytes_in: randInt(1100, 1260),
        bytes_out: randInt(900, 980),
        duration_ms: randInt(780, 860),
      }));
    },
  },
  {
    id: "lateral_movement",
    label: "Lateral movement",
    technique: "T1021",
    summary: "East-west movement from the DMZ toward the core banking database.",
    expect: "Lateral Movement · critical",
    generate: () => [
      {
        timestamp: at(0),
        log_type: "auth",
        source_ip: "10.20.0.11",
        destination_ip: "10.30.4.22",
        port: 22,
        protocol: "tcp",
        action: "lateral_movement",
        affected_host: "core-app-02",
        affected_user: "svc_payments",
        result: "success",
      },
      {
        timestamp: at(90_000),
        log_type: "network",
        source_ip: "10.30.4.22",
        destination_ip: "10.40.9.7",
        port: 1433,
        protocol: "tcp",
        action: "lateral_movement",
        affected_host: "db-core-01",
        affected_user: "svc_payments",
        bytes_in: 2210,
        bytes_out: 1180,
      },
    ],
  },
  {
    id: "data_exfil",
    label: "Data exfiltration",
    technique: "T1041",
    summary: "Bulk outbound transfer from the database tier to an external host.",
    expect: "Exfiltration · critical",
    generate: () => [
      {
        timestamp: at(0),
        log_type: "network",
        source_ip: "10.40.9.7",
        destination_ip: externalIp("203.0"),
        port: 443,
        protocol: "https",
        action: "data_exfiltration",
        affected_host: "db-core-01",
        affected_user: "svc_payments",
        bytes_in: 1420,
        bytes_out: 486_203_914,
        duration_ms: 214_880,
      },
    ],
  },
  {
    id: "iot_telnet",
    label: "Exposed IoT device",
    technique: "T1552",
    summary: "Branch camera reachable over cleartext Telnet with default credentials.",
    expect: "Credential Access · medium",
    generate: () => [
      {
        timestamp: at(0),
        log_type: "iot",
        source_ip: externalIp("192.0"),
        destination_ip: "10.60.2.31",
        port: 23,
        protocol: "telnet",
        action: "credential_abuse",
        affected_host: "branch-camera-07",
        device_id: "AXIS-P3245-07",
        firmware_version: "9.80.3",
        device_type: "ip_camera",
      },
    ],
  },
];


/**
 * The seven pipeline layers.
 *
 * Two labels each: what it does in plain words, and what it is actually called.
 * The plain label is always on screen; the technical one appears in analyst mode.
 * A risk officer watching a demo should be able to follow the pipeline without
 * knowing what "feature engineering" means.
 */
const LAYERS = [
  { plain: "Read the logs", technical: "Feature engineering", detail: "normalise, classify, extract" },
  { plain: "Spot what looks wrong", technical: "Detection", detail: "anomaly · patterns · intel · correlation" },
  { plain: "Join up related alerts", technical: "Campaign correlation", detail: "group alerts into one intrusion" },
  { plain: "Check the rulebook", technical: "Control mapping", detail: "CIS / OWASP benchmark retrieval" },
  { plain: "Write up what happened", technical: "Incident analysis", detail: "narrative and impact" },
  { plain: "Score the damage", technical: "CVSS scoring", detail: "3.1 base score and vector" },
  { plain: "Decide what to do", technical: "Response planning", detail: "playbook and approval gate" },
];

type Phase = "idle" | "running" | "done" | "error";

type RunResult = {
  events?: number;
  campaigns?: number;
  seconds?: number;
  message?: string;
};

export default function ScenarioReplayPage() {
  const router = useRouter();
  const { isAnalyst } = useDetail();
  const reduced = usePrefersReducedMotion();

  const [phase, setPhase] = useState<Phase>("idle");
  const [activeId, setActiveId] = useState<string | null>(null);
  const [logLines, setLogLines] = useState<RawLog[]>([]);
  const [layerIndex, setLayerIndex] = useState(-1);
  const [result, setResult] = useState<RunResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const logEnd = useRef<HTMLDivElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    logEnd.current?.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "end" });
  }, [logLines, reduced]);

  const submit = useCallback(
    async (logs: RawLog[], filename: string, label: string, id: string | null) => {
      setActiveId(id);
      setPhase("running");
      setError(null);
      setResult(null);
      setLogLines([]);
      setLayerIndex(-1);

      // Stream the raw records so it is visible that these are logs, not verdicts.
      for (let i = 0; i < logs.length; i += 1) {
        setLogLines((prev) => [...prev, logs[i]]);
        await new Promise((r) => setTimeout(r, Math.min(180, 900 / logs.length)));
      }

      // Advance the layer indicator while the request is in flight, then settle
      // on the real outcome.
      let running = true;
      const advance = (async () => {
        for (let i = 0; i < LAYERS.length && running; i += 1) {
          setLayerIndex(i);
          await new Promise((r) => setTimeout(r, 260));
        }
      })();

      try {
        const form = new FormData();
        form.append(
          "file",
          new Blob([JSON.stringify(logs, null, 2)], { type: "application/json" }),
          filename,
        );
        const res = await fetch("/api/run-pipeline", { method: "POST", body: form });
        const data = (await res.json().catch(() => ({}))) as RunResult;

        running = false;
        await advance;
        setLayerIndex(LAYERS.length);

        if (!res.ok) throw new Error(data?.message ?? `Pipeline returned ${res.status}`);

        setResult(data);
        setPhase("done");
      } catch (err) {
        running = false;
        await advance;
        setError(
          `${err instanceof Error ? err.message : String(err)} — start the backend with ` +
            `"uvicorn api_server:app --port 8000" and replay ${label} again.`,
        );
        setPhase("error");
      }
    },
    [],
  );

  const onUpload = useCallback(
    async (file: File) => {
      const text = await file.text();
      let logs: RawLog[];
      try {
        const parsed = JSON.parse(text);
        logs = Array.isArray(parsed) ? parsed : [parsed];
      } catch {
        // JSONL: one object per line. The backend accepts it either way, but
        // parsing here lets us stream the records for display.
        logs = text
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean)
          .map((l) => {
            try {
              return JSON.parse(l);
            } catch {
              return null;
            }
          })
          .filter(Boolean) as RawLog[];
      }
      if (logs.length === 0) {
        setError("No log records found in that file. Expecting a JSON array or JSONL.");
        setPhase("error");
        return;
      }
      await submit(logs, file.name, file.name, null);
    },
    [submit],
  );

  /**
   * Dropping a log file anywhere on the page replays it.
   *
   * The button in the header opens a picker and stays: dragging a file in is
   * quicker when you already have it in a window, and unusable if you are
   * driving by keyboard. Both routes end at the same onUpload.
   */
  const [dragging, setDragging] = useState(false);

  const onDragOver = useCallback((e: React.DragEvent) => {
    if (!e.dataTransfer.types.includes("Files")) return;
    e.preventDefault();
    setDragging(true);
  }, []);

  const onDragLeave = useCallback((e: React.DragEvent) => {
    // Fires when moving between children too, so only a leave that exits the
    // element itself counts.
    if (e.currentTarget.contains(e.relatedTarget as Node | null)) return;
    setDragging(false);
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      if (phase === "running") return;
      const file = e.dataTransfer.files?.[0];
      if (file) void onUpload(file);
    },
    [onUpload, phase],
  );

  const reset = () => {
    setPhase("idle");
    setActiveId(null);
    setLogLines([]);
    setLayerIndex(-1);
    setResult(null);
    setError(null);
  };

  const activeLabel = SCENARIOS.find((s) => s.id === activeId)?.label ?? "your logs";

  return (
    <div onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop} className="relative">
      {dragging ? (
        <div className="pointer-events-none fixed inset-0 z-50 flex items-center justify-center bg-ground/80 backdrop-blur-sm">
          <div className="flex items-center gap-3 rounded-lg border-2 border-dashed border-accent bg-surface px-6 py-5">
            <Upload className="h-5 w-5 text-accent" />
            <div>
              <p className="text-sm font-semibold text-ink">Drop the log file to replay it</p>
              <p className="text-[11px] text-muted">A JSON array, or JSONL with one record per line.</p>
            </div>
          </div>
        </div>
      ) : null}
    <Screen>
      {/* ── Lead ──────────────────────────────────────────────────────────── */}
      <Block>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 space-y-1.5">
            <p className="eyebrow">Replay an attack</p>
            <h1 className="text-2xl font-semibold tracking-tight text-ink">
              Send activity through the pipeline
            </h1>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            <input
              ref={fileInput}
              type="file"
              accept=".json,.jsonl,.txt,application/json"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) onUpload(f);
                e.target.value = "";
              }}
            />
            <button
              onClick={() => fileInput.current?.click()}
              disabled={phase === "running"}
              className="inline-flex items-center gap-1.5 rounded-md border border-rule bg-surface px-3 py-2 text-xs font-medium text-ink transition hover:border-rule hover:bg-raised disabled:opacity-50"
            >
              <Upload className="h-3.5 w-3.5" />
              Use your own logs
            </button>
            {phase !== "idle" ? (
              <button
                onClick={reset}
                className="rounded-md border border-rule px-3 py-2 text-xs font-medium text-muted transition hover:bg-raised hover:text-ink"
              >
                Start over
              </button>
            ) : null}
          </div>
        </div>

        <PlainEnglish>
          Pick an attack below and it replays as real activity — the same kind of
          records a bank&apos;s systems produce every second. Nothing on this page
          decides anything: every verdict, score and recommendation you see
          afterwards is worked out by the engine while you watch.
        </PlainEnglish>
      </Block>

      {/* ── Scenario picker ───────────────────────────────────────────────── */}
      {phase === "idle" ? (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {SCENARIOS.map((s) => (
            <motion.button
              key={s.id}
              whileHover={reduced ? undefined : { y: -2 }}
              transition={{ duration: 0.18, ease: EASE_OUT }}
              onClick={() => submit(s.generate(), `${s.id}.json`, s.label, s.id)}
              className="rise stagger-row group relative flex flex-col gap-2 overflow-hidden rounded-md border border-rule bg-surface p-4 text-left transition hover:border-accent-deep"
            >
              {/* The accent edge slides in on hover — the only affordance needed
                  to say "this is the thing you click". */}
              <span className="absolute left-0 top-0 h-full w-0.5 origin-top scale-y-0 bg-accent transition-transform duration-300 group-hover:scale-y-100" />

              <div className="flex items-start justify-between gap-2">
                <span className="text-sm font-medium text-ink">{s.label}</span>
                <ChevronRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-faint transition group-hover:translate-x-0.5 group-hover:text-accent" />
              </div>
              <span className="text-[11px] leading-relaxed text-muted">{s.summary}</span>

              {isAnalyst ? (
                <span className="mono mt-auto flex flex-wrap items-center gap-x-2 gap-y-1 pt-1 text-[10px] text-faint">
                  <span className="rounded border border-accent-deep px-1.5 py-0.5 text-accent">
                    {s.technique}
                  </span>
                  <span>expect → {s.expect}</span>
                </span>
              ) : null}
            </motion.button>
          ))}
        </div>
      ) : null}

      {/* ── Run view ──────────────────────────────────────────────────────── */}
      {phase !== "idle" ? (
        <PipelineTrace layerIndex={layerIndex} reduced={reduced} />
      ) : null}

      {phase !== "idle" ? (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] lg:items-start">
          {/* Pipeline progress — the centrepiece, always visible */}
          <Section
            title="What the engine is doing"
            hint={phase === "running" ? `Replaying ${activeLabel}` : undefined}
          >
            <ol className="space-y-0">
              {LAYERS.map((layer, i) => {
                const state = layerIndex > i ? "done" : layerIndex === i ? "active" : "waiting";
                const isLast = i === LAYERS.length - 1;
                return (
                  <li key={layer.plain} className="relative flex gap-3 pb-3.5 last:pb-0">
                    {!isLast ? (
                      <span
                        className={`absolute left-[7px] top-4 h-full w-px transition-colors duration-500 ${
                          state === "done" ? "bg-accent-deep" : "bg-rule"
                        }`}
                        aria-hidden
                      />
                    ) : null}

                    <span className="relative z-10 mt-0.5 flex h-3.5 w-3.5 shrink-0 items-center justify-center">
                      {state === "done" ? (
                        <motion.span
                          initial={reduced ? false : { scale: 0.4, opacity: 0 }}
                          animate={{ scale: 1, opacity: 1 }}
                          transition={{ duration: 0.22, ease: EASE_OUT }}
                        >
                          <CheckCircle2 className="h-3.5 w-3.5 text-accent" />
                        </motion.span>
                      ) : state === "active" ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" />
                      ) : (
                        <span className="h-1.5 w-1.5 rounded-full bg-rule" />
                      )}
                    </span>

                    <span className="min-w-0">
                      <span
                        className={`block text-xs transition-colors duration-300 ${
                          state === "waiting" ? "text-faint" : "font-medium text-ink"
                        }`}
                      >
                        {layer.plain}
                      </span>
                      {isAnalyst ? (
                        <span className="mono block text-[10px] text-faint">
                          {layer.technical} — {layer.detail}
                        </span>
                      ) : null}
                    </span>
                  </li>
                );
              })}
            </ol>
          </Section>

          {/* Outcome */}
          <div className="space-y-4">
            <AnimatePresence mode="wait">
              {phase === "done" && result ? (
                <motion.div
                  key="done"
                  initial={reduced ? false : { opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.34, ease: EASE_OUT }}
                  className="space-y-3.5 rounded-md border border-accent-deep bg-accent/8 p-4"
                >
                  <p className="flex items-center gap-2 text-xs font-semibold text-accent">
                    <CheckCircle2 className="h-4 w-4" />
                    Done — the engine reached its verdict
                  </p>

                  <div className="grid grid-cols-3 gap-px overflow-hidden rounded border border-rule bg-rule">
                    <ResultFigure label="Records read" value={result.events} />
                    <ResultFigure label="Attacks found" value={result.campaigns} />
                    <ResultFigure
                      label="Seconds taken"
                      value={result.seconds}
                      decimals={2}
                    />
                  </div>

                  <div className="flex gap-2">
                    <button
                      onClick={() => router.push("/dashboard")}
                      className="flex-1 rounded-md bg-accent px-3 py-2 text-[11px] font-semibold text-ground transition hover:opacity-90"
                    >
                      See what it found
                    </button>
                    {(result.campaigns ?? 0) > 0 ? (
                      <button
                        onClick={() => router.push("/campaigns")}
                        className="flex-1 rounded-md border border-rule px-3 py-2 text-[11px] font-semibold text-ink transition hover:bg-raised"
                      >
                        See the full attack
                      </button>
                    ) : null}
                  </div>
                </motion.div>
              ) : null}

              {phase === "error" ? (
                <motion.div
                  key="error"
                  initial={reduced ? false : { opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, ease: EASE_OUT }}
                  className="space-y-2 rounded-md border border-sev-critical/40 bg-sev-critical/10 p-4"
                >
                  <p className="flex items-center gap-2 text-xs font-semibold text-sev-critical">
                    <AlertTriangle className="h-4 w-4" />
                    The engine did not run
                  </p>
                  <p className="text-[11px] leading-relaxed text-muted">{error}</p>
                  <p className="text-[10px] leading-relaxed text-faint">
                    Nothing was recorded. This page never invents results when the
                    engine is unreachable — an empty dashboard is the honest answer.
                  </p>
                </motion.div>
              ) : null}
            </AnimatePresence>

            {/* The raw records: available, not imposed. */}
            <Reveal
              label="Show the raw activity that was sent"
              count={logLines.length}
              defaultOpen={isAnalyst}
            >
              <div className="overflow-hidden rounded border border-rule bg-sunk">
                <div className="flex items-center gap-2 border-b border-rule px-3 py-2">
                  <Terminal className="h-3.5 w-3.5 text-faint" />
                  <span className="eyebrow">Exactly what was submitted</span>
                </div>
                <div className="mono max-h-[360px] min-h-[120px] space-y-1 overflow-y-auto p-3 text-[10.5px] leading-relaxed">
                  {logLines.map((line, i) => (
                    <div key={i} className="flex gap-2 text-muted">
                      <span className="shrink-0 text-faint">
                        {String(i + 1).padStart(2, "0")}
                      </span>
                      <span className="min-w-0 break-all">
                        <span className="text-faint">
                          {String(line.timestamp ?? "").slice(11, 19)}
                        </span>{" "}
                        <span className="text-accent">{String(line.log_type ?? "")}</span>{" "}
                        <span className="text-ink">{String(line.source_ip ?? "")}</span>
                        {line.destination_ip ? (
                          <>
                            <span className="text-faint"> → </span>
                            <span className="text-ink">{String(line.destination_ip)}</span>
                          </>
                        ) : null}
                        {line.action ? (
                          <span className="text-sev-medium"> {String(line.action)}</span>
                        ) : null}
                        {/* A bare 486203914 is unreadable; 463.7 MB is the point
                            of the exfiltration scenario. */}
                        {Number(line.bytes_out) > 1_000_000 ? (
                          <span className="font-semibold text-sev-critical">
                            {" "}
                            {formatBytes(line.bytes_out)} out
                          </span>
                        ) : null}
                        {line.url ? <span className="text-faint"> {String(line.url)}</span> : null}
                        {line.affected_user ? (
                          <span className="text-faint"> user={String(line.affected_user)}</span>
                        ) : null}
                      </span>
                    </div>
                  ))}
                  <div ref={logEnd} />
                </div>
              </div>
            </Reveal>
          </div>
        </div>
      ) : null}
    </Screen>
    </div>
  );
}

/** One cell of the outcome grid. Counts up so the number registers. */
function ResultFigure({
  label,
  value,
  decimals = 0,
}: {
  label: string;
  value: number | undefined;
  decimals?: number;
}) {
  const animated = useCountUp(Number(value ?? 0), 700);
  return (
    <div className="bg-surface px-3 py-2.5">
      <p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-faint">{label}</p>
      <p className="figure mt-1 text-lg font-semibold text-ink">
        {value == null ? "—" : animated.toFixed(decimals)}
      </p>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Seven traces converging on the record stream.

   Decoration, and marked as such: the ordered list below is what actually
   reports progress, because it carries the stage names and reads correctly to a
   screen reader. This is the same information as a picture, for the wall
   display.

   The control points give every branch a real horizontal sweep. A near-vertical
   cubic collapses to a zero-width bounding box, and both stroke animation and
   the glow filter stop rendering when that happens — which is why the two outer
   branches bow one way and the rest the other rather than fanning symmetrically.
   ───────────────────────────────────────────────────────────────────────────── */

const NODE_X = [100, 300, 500, 700, 900, 1100, 1300];
const ENTRY_X = [500, 566, 633, 700, 766, 833, 900];
const TRACE_PATHS = NODE_X.map((nx, i) => {
  const ex = ENTRY_X[i];
  const bow = i <= 3 ? 46 : -46;
  return `M ${nx} 0 C ${nx + bow} 70, ${ex - bow} 120, ${ex} 190`;
});

function PipelineTrace({ layerIndex, reduced }: { layerIndex: number; reduced: boolean }) {
  return (
    <div className="pointer-events-none relative h-[120px] w-full overflow-hidden md:h-[150px]" aria-hidden>
      <svg viewBox="0 0 1400 200" preserveAspectRatio="none" className="absolute inset-0 h-full w-full">
        <defs>
          <marker
            id="trace-arrow"
            viewBox="0 0 10 10"
            refX="5"
            refY="5"
            markerWidth="4"
            markerHeight="4"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--accent)" />
          </marker>
        </defs>

        {TRACE_PATHS.map((d, i) => {
          const finished = layerIndex > i;
          const active = layerIndex === i;
          const lit = finished || active;

          return (
            <g key={NODE_X[i]}>
              <path
                id={`trace-path-${i}`}
                d={d}
                fill="none"
                stroke="var(--rule)"
                strokeWidth="2"
                vectorEffect="non-scaling-stroke"
              />

              {lit ? (
                <>
                  {/* A CSS drop-shadow rather than an SVG filter: filters are the
                      other thing that fails on a degenerate bounding box. */}
                  <path
                    d={d}
                    fill="none"
                    stroke="var(--accent)"
                    strokeWidth="8"
                    strokeLinecap="round"
                    opacity={finished ? 0.14 : 0.22}
                    style={{ filter: "drop-shadow(0 0 6px var(--accent))" }}
                    vectorEffect="non-scaling-stroke"
                  />
                  <motion.path
                    d={d}
                    fill="none"
                    stroke="var(--accent)"
                    strokeWidth="2.5"
                    strokeLinecap="round"
                    markerEnd="url(#trace-arrow)"
                    vectorEffect="non-scaling-stroke"
                    initial={reduced ? false : { pathLength: 0 }}
                    animate={{ pathLength: 1 }}
                    transition={{ duration: 0.55, ease: EASE_OUT }}
                  />
                </>
              ) : null}

              {/* The travelling dot is the only part that repeats, so it is the
                  only part reduced motion has to drop. */}
              {active && !reduced ? (
                <circle r={4} fill="var(--accent)">
                  <animateMotion dur="1.15s" repeatCount="indefinite">
                    <mpath href={`#trace-path-${i}`} />
                  </animateMotion>
                </circle>
              ) : null}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

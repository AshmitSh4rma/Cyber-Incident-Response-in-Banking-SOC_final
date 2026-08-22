"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Loader2,
  Play,
  Terminal,
  Upload,
} from "lucide-react";
import { FileUpload } from "@/components/ui/file-upload";

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
    summary: "Executable dropped into an writable web directory for persistence.",
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

const LAYERS = [
  { label: "Feature engineering", detail: "normalise, classify, extract" },
  { label: "Detection", detail: "anomaly · patterns · intel · correlation" },
  { label: "Campaign correlation", detail: "group alerts into intrusions" },
  { label: "Control mapping", detail: "CIS / OWASP benchmark retrieval" },
  { label: "Incident analysis", detail: "narrative and CVSS metrics" },
  { label: "CVSS scoring", detail: "3.1 base score and vector" },
  { label: "Response planning", detail: "playbook and approval gate" },
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
  const [phase, setPhase] = useState<Phase>("idle");
  const [activeId, setActiveId] = useState<string | null>(null);
  const [logLines, setLogLines] = useState<RawLog[]>([]);
  const [layerIndex, setLayerIndex] = useState(-1);
  const [result, setResult] = useState<RunResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const logEnd = useRef<HTMLDivElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    logEnd.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [logLines]);

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
    async (files: File[]) => {
      const file = files[0];
      if (!file) return;
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

  const reset = () => {
    setPhase("idle");
    setActiveId(null);
    setLogLines([]);
    setLayerIndex(-1);
    setResult(null);
    setError(null);
  };

  return (
    <div className="mx-auto max-w-[1400px] space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="space-y-1.5">
          <p className="eyebrow">Scenario replay</p>
          <h1 className="text-2xl font-semibold tracking-tight text-ink">
            Send telemetry through the pipeline
          </h1>
          <p className="max-w-2xl text-xs leading-relaxed text-muted">
            Each scenario emits raw log records and nothing else. Every verdict,
            score, control mapping and campaign grouping you see afterwards was
            decided by the backend, not by this page.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {phase !== "idle" && (
            <button
              onClick={reset}
              className="rounded-md border border-rule px-3 py-2 text-xs font-medium text-ink transition hover:bg-raised"
            >
              Reset
            </button>
          )}
        </div>
      </div>



      {/* Scenario picker */}
      {phase === "idle" && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {SCENARIOS.map((s) => (
            <button
              key={s.id}
              onClick={() => submit(s.generate(), `${s.id}.json`, s.label, s.id)}
              className="group flex flex-col gap-2 rounded-md border border-rule bg-surface p-4 text-left transition hover:border-accent-deep hover:bg-raised"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="mono rounded border border-rule bg-raised px-1.5 py-0.5 text-[10px] text-accent">
                  {s.technique}
                </span>
                <ChevronRight className="h-3.5 w-3.5 text-faint transition group-hover:translate-x-0.5 group-hover:text-muted" />
              </div>
              <span className="text-sm font-medium text-ink">{s.label}</span>
              <span className="text-[11px] leading-relaxed text-muted">{s.summary}</span>
              <span className="mono mt-auto pt-1 text-[10px] text-faint">
                expect → {s.expect}
              </span>
            </button>
          ))}
        </div>
      )}

      {/* Run view */}
      {phase !== "idle" && (
        <div className="grid gap-5 lg:grid-cols-5">
          {/* Raw log stream */}
          <div className="flex flex-col overflow-hidden rounded-md border border-rule bg-sunk lg:col-span-3">
            <div className="flex items-center gap-2 border-b border-rule px-4 py-2.5">
              <Terminal className="h-3.5 w-3.5 text-faint" />
              <span className="eyebrow">Raw records submitted</span>
              <span className="mono ml-auto text-[10px] text-faint">
                {logLines.length} record{logLines.length === 1 ? "" : "s"}
              </span>
            </div>
            <div className="mono max-h-[420px] min-h-[240px] space-y-1 overflow-y-auto p-4 text-[10.5px] leading-relaxed">
              {logLines.map((line, i) => (
                <div key={i} className="flex gap-2 text-muted">
                  <span className="shrink-0 text-faint">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <span className="min-w-0 break-all">
                    <span className="text-faint">{String(line.timestamp ?? "").slice(11, 19)}</span>{" "}
                    <span className="text-accent">{String(line.log_type ?? "")}</span>{" "}
                    <span className="text-ink">{String(line.source_ip ?? "")}</span>
                    {line.destination_ip ? (
                      <>
                        <span className="text-faint"> → </span>
                        <span className="text-ink">{String(line.destination_ip)}</span>
                      </>
                    ) : null}
                    {line.action ? <span className="text-sev-medium"> {String(line.action)}</span> : null}
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

          {/* Pipeline progress + outcome */}
          <div className="space-y-4 lg:col-span-2">
            <div className="rounded-md border border-rule bg-surface p-4">
              <p className="eyebrow mb-3">Pipeline</p>
              <ol className="space-y-2">
                {LAYERS.map((layer, i) => {
                  const state = layerIndex > i ? "done" : layerIndex === i ? "active" : "waiting";
                  return (
                    <li key={layer.label} className="flex items-start gap-2.5">
                      <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center">
                        {state === "done" ? (
                          <CheckCircle2 className="h-3.5 w-3.5 text-sev-benign" />
                        ) : state === "active" ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" />
                        ) : (
                          <span className="h-1.5 w-1.5 rounded-full bg-rule-soft" />
                        )}
                      </span>
                      <span className="min-w-0">
                        <span
                          className={[
                            "block text-xs",
                            state === "waiting" ? "text-faint" : "text-ink",
                          ].join(" ")}
                        >
                          {layer.label}
                        </span>
                        <span className="block text-[10px] text-faint">{layer.detail}</span>
                      </span>
                    </li>
                  );
                })}
              </ol>
            </div>

            {phase === "done" && result && (
              <div className="space-y-3 rounded-md border border-sev-benign/30 bg-sev-benign/10 p-4">
                <p className="flex items-center gap-2 text-xs font-semibold text-sev-benign">
                  <CheckCircle2 className="h-4 w-4" />
                  Pipeline complete
                </p>
                <dl className="space-y-1.5 text-[11px]">
                  {[
                    ["Records scored", result.events],
                    ["Campaigns correlated", result.campaigns],
                    ["Wall clock", result.seconds != null ? `${result.seconds}s` : undefined],
                  ]
                    .filter(([, v]) => v !== undefined)
                    .map(([k, v]) => (
                      <div key={String(k)} className="flex justify-between gap-3">
                        <dt className="text-muted">{k}</dt>
                        <dd className="mono font-semibold text-ink">{String(v)}</dd>
                      </div>
                    ))}
                </dl>
                <div className="flex gap-2 pt-1">
                  <button
                    onClick={() => router.push("/dashboard")}
                    className="flex-1 rounded-md bg-accent px-3 py-2 text-[11px] font-semibold text-sunk transition hover:opacity-90"
                  >
                    Open dashboard
                  </button>
                  {(result.campaigns ?? 0) > 0 && (
                    <button
                      onClick={() => router.push("/campaigns")}
                      className="flex-1 rounded-md border border-rule px-3 py-2 text-[11px] font-semibold text-ink transition hover:bg-raised"
                    >
                      View campaigns
                    </button>
                  )}
                </div>
              </div>
            )}

            {phase === "error" && (
              <div className="space-y-2 rounded-md border border-sev-critical/40 bg-sev-critical/15 p-4">
                <p className="flex items-center gap-2 text-xs font-semibold text-sev-critical">
                  <AlertTriangle className="h-4 w-4" />
                  Pipeline did not run
                </p>
                <p className="text-[11px] leading-relaxed text-muted">{error}</p>
                <p className="text-[10px] text-faint">
                  No incidents were created. Nothing on this page fabricates results
                  when the backend is unreachable.
                </p>
              </div>
            )}

            {phase === "running" && (
              <div className="flex items-center gap-2 rounded-md border border-rule bg-surface px-4 py-3 text-[11px] text-muted">
                <Play className="h-3.5 w-3.5 text-accent" />
                Replaying {SCENARIOS.find((s) => s.id === activeId)?.label ?? "uploaded logs"}…
              </div>
            )}
          </div>
        </div>
      )}

      {/* File Upload Zone - Centered at bottom */}
      {phase === "idle" && (
        <div className="w-full max-w-xl mx-auto mt-12 border border-dashed border-rule-soft bg-surface rounded-xl overflow-hidden shadow-lg">
          <FileUpload onChange={onUpload} />
        </div>
      )}
    </div>
  );
}

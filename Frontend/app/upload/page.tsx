"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  CheckCircle2,
  ChevronRight,
  Loader2,
  Play,
  Terminal,
  Upload,
  Zap
} from "lucide-react";
import { motion } from "framer-motion";

const randInt = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;
const externalIp = (prefix: string) => `${prefix}.${randInt(1, 254)}.${randInt(1, 254)}`;
const at = (offsetMs: number) => new Date(Date.now() - 3_600_000 + offsetMs).toISOString();

type RawLog = Record<string, string | number | null | undefined>;

type Scenario = {
  id: string;
  label: string;
  technique: string;
  summary: string;
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
];

const LAYERS = [
  { prefix: "01", short: "FEAT_ENG", label: "Feature engineering", detail: "normalise, classify, extract" },
  { prefix: "02", short: "DET_ENGINE", label: "Detection", detail: "anomaly · patterns · intel · correlation" },
  { prefix: "03", short: "CAM_CORR", label: "Campaign correlation", detail: "group alerts into intrusions" },
  { prefix: "04", short: "CTL_MAP", label: "Control mapping", detail: "CIS / OWASP benchmark retrieval" },
  { prefix: "05", short: "AI_ANAL", label: "Incident analysis", detail: "narrative and CVSS metrics" },
  { prefix: "06", short: "CVSS_SC", label: "CVSS scoring", detail: "3.1 base score and vector" },
  { prefix: "07", short: "RESP_PLN", label: "Response planning", detail: "playbook and approval gate" },
];

type Phase = "idle" | "running" | "done" | "error";

type RunResult = {
  events?: number;
  campaigns?: number;
  seconds?: number;
  message?: string;
};

// SVG geometry based on 1400x200 viewBox.
// Every branch is given a real horizontal sweep via its control points — a
// near-vertical path (the old centre branch) collapses to a zero-width
// bounding box, which breaks stroke animation and glow rendering.
const NODE_X = [100, 300, 500, 700, 900, 1100, 1300];
const ENTRY_X = [500, 566, 633, 700, 766, 833, 900];
const TRACE_PATHS = NODE_X.map((nx, i) => {
  const ex = ENTRY_X[i];
  const bow = i <= 3 ? 46 : -46;
  return `M ${nx} 0 C ${nx + bow} 70, ${ex - bow} 120, ${ex} 190`;
});

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
  const runIdRef = useRef(0);

  useEffect(() => {
    logEnd.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [logLines]);

  const submit = useCallback(
    async (logs: RawLog[], filename: string, label: string, id: string | null) => {
      runIdRef.current += 1;
      const currentRunId = runIdRef.current;

      setActiveId(id);
      setPhase("running");
      setError(null);
      setResult(null);
      setLogLines([]);
      setLayerIndex(-1);

      // Advance layers and stream logs sequentially
      const advance = (async () => {
        const total = LAYERS.length;
        const count = logs.length;
        const perLayer = Math.floor(count / total);
        const remainder = count % total;
        let cursor = 0;

        for (let i = 0; i < total; i += 1) {
          if (runIdRef.current !== currentRunId) return;
          setLayerIndex(i);

          // Every layer must ingest at least one record. Scenarios with fewer
          // records than layers cycle through what was submitted instead of
          // leaving the later layers empty.
          const batch = count >= total ? perLayer + (i < remainder ? 1 : 0) : 1;

          for (let j = 0; j < batch; j += 1) {
            if (runIdRef.current !== currentRunId) return;
            setLogLines((prev) => [...prev, logs[cursor % count]]);
            cursor += 1;
            await new Promise((r) => setTimeout(r, 150));
          }

          if (runIdRef.current !== currentRunId) return;
          await new Promise((r) => setTimeout(r, 600));
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

        await advance;
        if (runIdRef.current !== currentRunId) return;

        setLayerIndex(LAYERS.length);

        if (!res.ok) throw new Error(data?.message ?? `Pipeline returned ${res.status}`);

        setResult(data);
        setPhase("done");
      } catch (err) {
        await advance;
        if (runIdRef.current !== currentRunId) return;

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
        logs = text
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean)
          .map((l) => {
            try { return JSON.parse(l); } catch { return null; }
          })
          .filter(Boolean) as RawLog[];
      }
      if (logs.length === 0) {
        setError("No log records found in that file.");
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

  const activeScenario = SCENARIOS.find((s) => s.id === activeId);

  return (
    <div className="min-h-screen bg-[#020202] text-slate-300">
      <div className="mx-auto max-w-[1400px] p-6 space-y-8">

        {/* Top Header & Scenario Picker / Status */}
        <div className="flex items-center justify-between border-b border-slate-900 pb-4">
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white">Send telemetry through the pipeline</h1>
            <div className="mt-2 text-sm text-slate-500 flex items-center gap-2">
              <span className="uppercase tracking-widest text-[10px] font-bold text-slate-600">Scenario Replay</span>
            </div>
          </div>
          <div className="flex gap-3">
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
              className="inline-flex items-center gap-2 rounded border border-slate-800 bg-[#0a0a0a] px-4 py-2 text-xs font-semibold text-slate-300 transition hover:border-slate-700 hover:text-white disabled:opacity-50"
            >
              <Upload className="h-3.5 w-3.5" />
              Upload your own logs
            </button>
            <button
              onClick={reset}
              className="inline-flex items-center gap-2 rounded border border-slate-800 bg-[#0a0a0a] px-4 py-2 text-xs font-semibold text-slate-300 transition hover:border-slate-700 hover:text-white"
            >
              Reset Simulation
            </button>
          </div>
        </div>

        {/* Selected Scenario Bar */}
        {activeScenario && (
          <div className="flex items-center gap-3 rounded border border-slate-800 bg-[#050505] px-4 py-3 shadow-[0_0_20px_rgba(0,0,0,0.5)]">
            <span className="flex h-6 w-6 items-center justify-center rounded bg-slate-900">
              <Terminal className="h-3.5 w-3.5 text-slate-500" />
            </span>
            <p className="text-sm">
              <span className="text-slate-500">Scenario: </span>
              <span className="font-mono text-emerald-400 font-semibold">{activeScenario.technique}</span>
              <span className="text-slate-200 ml-2">- {activeScenario.label}</span>
              <span className="text-slate-500 ml-2">({activeScenario.expect})</span>
            </p>
          </div>
        )}

        {/* Pipeline Visualizer Layout */}
        {phase !== "idle" && (
          <div className="relative mt-8">

            {/* Top Row: 7 Nodes */}
            <div className="relative z-10 flex w-full justify-between gap-4">
              {LAYERS.map((layer, i) => {
                const isFinished = layerIndex > i;
                const isActive = layerIndex === i;

                const baseClass = "flex-1 flex flex-col rounded-lg border p-3 transition-all duration-300";
                const stateClass = isActive
                  ? "border-emerald-500 bg-[#05100a] shadow-[0_0_15px_rgba(16,185,129,0.3)]"
                  : isFinished
                    ? "border-emerald-900/50 bg-[#050a07]"
                    : "border-slate-800/80 bg-[#080808]";

                return (
                  <div key={i} className={`${baseClass} ${stateClass}`}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`font-mono text-[10px] font-bold ${isActive || isFinished ? 'text-emerald-400' : 'text-slate-600'}`}>
                        {layer.prefix}
                      </span>
                      <span className={`font-mono text-xs font-bold tracking-wider ${isActive ? 'text-white' : isFinished ? 'text-emerald-500/80' : 'text-slate-400'}`}>
                        {layer.short}
                      </span>
                      {isActive && <Zap className="h-3 w-3 text-emerald-400 ml-auto animate-pulse" />}
                    </div>
                    <h3 className={`text-xs font-medium mb-1 ${isActive ? 'text-white' : 'text-slate-300'}`}>{layer.label}</h3>
                    <p className="text-[9px] text-slate-500 leading-tight mb-4 flex-1">{layer.detail}</p>

                    <div className="flex items-center gap-1.5 mt-auto">
                      {isFinished ? (
                        <span className="text-[10px] text-emerald-500 flex items-center gap-1">
                          Complete Check <CheckCircle2 className="h-3 w-3" />
                        </span>
                      ) : isActive ? (
                        <span className="text-[10px] text-emerald-400 flex items-center gap-1 font-semibold">
                          Processing Zap <Zap className="h-3 w-3 animate-pulse" />
                        </span>
                      ) : (
                        <span className="text-[10px] text-slate-600 flex items-center gap-1">
                          Idle Circle <span className="h-2.5 w-2.5 rounded-full border border-slate-600"></span>
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Converging SVG Traces */}
            <div className="pointer-events-none relative z-0 h-[200px] w-full">
              <svg
                viewBox="0 0 1400 200"
                preserveAspectRatio="none"
                className="absolute inset-0 h-full w-full"
              >
                <defs>
                  <marker id="arrow-idle" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#1e293b" />
                  </marker>
                  <marker id="arrow-active" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#10b981" />
                  </marker>
                </defs>

                {TRACE_PATHS.map((d, i) => {
                  const isFinished = layerIndex > i;
                  const isActive = layerIndex === i;
                  const isLit = isActive || isFinished;

                  return (
                    <g key={i}>
                      {/* Base dim line */}
                      <path
                        id={`trace-path-${i}`}
                        d={d}
                        fill="none"
                        stroke="#0f172a"
                        strokeWidth="3"
                        markerEnd="url(#arrow-idle)"
                        vectorEffect="non-scaling-stroke"
                      />

                      {/* Lit underlay glow — CSS drop-shadow instead of an SVG
                        filter, which fails on near-zero-width paths */}
                      {isLit && (
                        <motion.path
                          d={d}
                          fill="none"
                          stroke="#10b981"
                          strokeWidth="9"
                          strokeLinecap="round"
                          opacity={isFinished ? 0.16 : 0.24}
                          style={{ filter: "drop-shadow(0 0 6px rgba(16,185,129,0.55))" }}
                          initial={{ pathLength: 1 }}
                          vectorEffect="non-scaling-stroke"
                          markerEnd="url(#arrow-active)"
                        />
                      )}

                      {/* Solid lit line: draws in once when the stage activates,
                        then stays put for the rest of the run */}
                      {isLit && (
                        <motion.path
                          d={d}
                          fill="none"
                          stroke="#10b981"
                          strokeWidth="3"
                          strokeLinecap="round"
                          initial={{ pathLength: 1 }}
                          vectorEffect="non-scaling-stroke"
                          markerEnd="url(#arrow-active)"
                        />
                      )}

                      {/* Pulse travelling along the trace while it processes.
                        A straight-line path still animates reliably with SMIL. */}
                      {isActive && (
                        <>
                          <motion.path
                            d={d}
                            fill="none"
                            stroke="#34d399"
                            strokeWidth="3"
                            strokeLinecap="round"
                            style={{ filter: "drop-shadow(0 0 4px rgba(52,211,153,0.7))" }}
                            initial={{ pathLength: 0, opacity: 0 }}
                            animate={{ pathLength: 1, opacity: 1 }}
                            transition={{ duration: 0.55, ease: "easeOut" }}
                            vectorEffect="non-scaling-stroke"
                            markerEnd="url(#arrow-active)"
                          />
                          <circle r={4} fill="#34d399">
                            <animateMotion dur="1.15s" repeatCount="indefinite">
                              <mpath href={`#trace-path-${i}`} />
                            </animateMotion>
                          </circle>
                        </>
                      )}
                    </g>
                  );
                })}
              </svg>
            </div>

            {/* Central Core Terminal */}
            <div className="relative z-10 mx-auto -mt-6 w-full max-w-[900px] overflow-hidden rounded-xl border border-slate-800 bg-[#050505] shadow-2xl">

              {/* Terminal Header */}
              <div className="flex items-center justify-between border-b border-slate-800/80 bg-[#0a0a0a] px-4 py-3">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-sm font-bold text-slate-300">
                    {">_ RAW RECORDS SUBMITTED"}
                  </span>
                </div>
                <span className="rounded-full border border-slate-800 bg-[#080808] px-3 py-1 font-mono text-[10px] text-slate-500">
                  ({logLines.length} records ingested)
                </span>
              </div>

              {/* Terminal Body: Logs */}
              <div className="font-mono relative h-[320px] flex-col space-y-1.5 overflow-y-auto p-5 text-[11px] leading-relaxed">
                {/* Subtle Grid Background */}
                <div className="pointer-events-none absolute inset-0 opacity-[0.03]" style={{ backgroundImage: 'linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)', backgroundSize: '40px 40px' }}></div>

                {logLines.length === 0 && phase === "running" && (
                  <div className="flex h-full items-center justify-center text-slate-700">
                    Awaiting payload injection...
                  </div>
                )}
                {logLines.map((line, i) => (
                  <motion.div
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    key={i}
                    className="relative z-10 flex gap-3 text-slate-400"
                  >
                    <span className="shrink-0 text-slate-600">{String(i + 1).padStart(2, "0")}</span>
                    <span className="min-w-0 break-all">
                      <span className="text-slate-500">{String(line.timestamp ?? "").slice(11, 19)}</span>{" "}
                      <span className="text-emerald-500/80">{String(line.log_type ?? "")}</span>{" "}
                      <span className="text-slate-300">{String(line.source_ip ?? "")}</span>
                      {line.destination_ip && (
                        <>
                          <span className="text-slate-600"> → </span>
                          <span className="text-slate-300">{String(line.destination_ip)}</span>
                        </>
                      )}
                      {line.action && <span className="text-emerald-400/80 font-bold"> {String(line.action)}</span>}
                      {line.url && <span className="text-slate-500"> {String(line.url)}</span>}
                    </span>
                  </motion.div>
                ))}
                <div ref={logEnd} className="h-8" />

                {/* Terminal Footer Overlay (appears when done) */}
                {phase === "done" && result && (
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mx-auto mt-6 w-[95%] rounded-lg border border-emerald-900 bg-[#05100a] p-5 shadow-[0_0_30px_rgba(16,185,129,0.15)]"
                  >
                    <div className="text-center">
                      <h3 className="font-mono text-base font-bold text-emerald-400 flex items-center justify-center gap-2">
                        [ Pipeline complete <CheckCircle2 className="h-4 w-4" /> ]
                      </h3>
                      <p className="mt-3 font-mono text-[11px] text-slate-400">
                        Records scored: <span className="text-emerald-300">{result.events}</span> <span className="text-slate-700 mx-2">|</span>
                        Campaigns Correlated: <span className="text-emerald-300">{result.campaigns}</span> <span className="text-slate-700 mx-2">|</span>
                        Wall clock execution: <span className="text-emerald-300">{result.seconds}s</span>
                      </p>

                      <div className="mt-6 flex justify-center gap-4">
                        <button
                          onClick={() => router.push("/dashboard")}
                          className="rounded border border-emerald-500 bg-emerald-500/10 px-6 py-2 font-mono text-[11px] font-bold text-emerald-400 transition hover:bg-emerald-500 hover:text-black shadow-[0_0_15px_rgba(16,185,129,0.2)]"
                        >
                          Open Dashboard
                        </button>
                        {(result.campaigns ?? 0) > 0 && (
                          <button
                            onClick={() => router.push("/campaigns")}
                            className="rounded border border-slate-700 bg-black px-6 py-2 font-mono text-[11px] font-bold text-slate-300 transition hover:border-slate-500 hover:text-white"
                          >
                            View Campaigns
                          </button>
                        )}
                      </div>
                    </div>
                  </motion.div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Scenario Picker Grid (if no active scenario yet) */}
        {phase === "idle" && (
          <div className="pt-8">
            <h2 className="mb-4 font-mono text-sm tracking-wider text-slate-500">AVAILABLE SCENARIOS</h2>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {SCENARIOS.map((s) => (
                <button
                  key={s.id}
                  onClick={() => {
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                    submit(s.generate(), `${s.id}.json`, s.label, s.id);
                  }}
                  className="group flex flex-col gap-2 rounded-lg border border-slate-800/80 bg-[#0a0a0a] p-5 text-left transition-all hover:border-emerald-500/50 hover:bg-[#0a0f0c]"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono rounded border border-slate-800 bg-black px-1.5 py-0.5 text-[10px] text-emerald-500">
                      {s.technique}
                    </span>
                    <Play className="h-4 w-4 text-slate-600 transition group-hover:text-emerald-400" />
                  </div>
                  <span className="text-sm font-semibold text-slate-200">{s.label}</span>
                  <span className="text-[11px] leading-relaxed text-slate-500 flex-1">{s.summary}</span>
                  <span className="font-mono mt-auto pt-3 text-[10px] text-slate-600">
                    expect → <span className="text-slate-400">{s.expect}</span>
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}

      </div>
    </div>
  );
}

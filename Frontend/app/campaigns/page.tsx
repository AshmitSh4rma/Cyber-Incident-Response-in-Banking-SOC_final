"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ChevronDown,
  Globe,
  Monitor,
  User,
  Shield,
  Activity,
  AlertCircle
} from "lucide-react";

// ─── TYPES ──────────────────────────────────────────────────────────────────
type EventLog = {
  id: string;
  timestamp: string;
  description: string;
  stage: string;
  score: number;
};

type Campaign = {
  id: string;
  title: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  timestamp: string;
  alertsCount: number;
  lifecyclePercent: number;
  furthestStage: string;
  stagesReached: number;
  totalStages: number;
  sourceIp: string;
  targetAsset: string;
  correlationReason: string;
  deadlineString: string;
  deadlineActive: boolean;
  materialityText: string;
  threatActor: string;
  assetsInvolved: string[];
  techniques: string[];
  aiSummary: string;
  eventsArray: EventLog[];
  killChain: { stage: string; active: boolean }[];
};

// ─── MOCK DATA ──────────────────────────────────────────────────────────────
const KILL_CHAIN_STAGES = [
  "RECON", "REGDEV", "ACCESS", "EXEC", "PERSIST", "PRIVESC", "STEALTH",
  "GETIMP", "CREDS", "DISCOVER", "LATERAL", "COLLECT", "C2", "EXFIL", "IMPACT"
];

const MOCK_CAMPAIGNS: Campaign[] = [
  {
    id: "CMP-001",
    title: "Reconnaissance originating from 198.51.97.39",
    severity: "MEDIUM",
    timestamp: "22 Aug at 04:01 PM",
    alertsCount: 6,
    lifecyclePercent: 7,
    furthestStage: "Reconnaissance",
    stagesReached: 1,
    totalStages: 15,
    sourceIp: "198.51.97.39",
    targetAsset: "dmz-web-01",
    correlationReason: "Deterministic: Same source IP address 198.51.97.39",
    deadlineString: "03:59:59",
    deadlineActive: false,
    materialityText: "Muted secondary text: No deadline raised. Materiality threshold not met (Context: Activity limited to reconnaissance).",
    threatActor: "Unknown",
    assetsInvolved: ["dmz-web-01"],
    techniques: ["T1595.001"],
    aiSummary: "6 separate alerts describe a sequence of activity involving dmz-web-01, beginning at 198.51.97.39. Active pre-compromise reconnaissance.",
    eventsArray: Array.from({ length: 6 }).map((_, i) => ({
      id: `evt-${1000 + i}`,
      timestamp: `2026-08-22T16:0${i}:00Z`,
      description: "Port scan detected on DMZ web server",
      stage: "Reconnaissance",
      score: 4.5,
    })),
    killChain: KILL_CHAIN_STAGES.map((s, i) => ({ stage: s, active: i === 0 })),
  },
];

// ─── COMPONENTS ─────────────────────────────────────────────────────────────

function CampaignAccordion({ campaign }: { campaign: Campaign }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [expandedLogsId, setExpandedLogsId] = useState<string | null>(null);

  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case "CRITICAL": return "text-red-500 bg-red-500/10 border-red-500/30";
      case "HIGH": return "text-orange-500 bg-orange-500/10 border-orange-500/30";
      case "MEDIUM": return "text-amber-500 bg-amber-500/10 border-amber-500/30";
      default: return "text-emerald-500 bg-emerald-500/10 border-emerald-500/30";
    }
  };

  return (
    <div className={`rounded-xl border transition-colors duration-300 overflow-hidden bg-[#050505] ${isExpanded ? "border-emerald-500" : "border-slate-800"}`}>
      {/* ── HEADER CARD ── */}
      <div 
        className="p-5 cursor-pointer relative group"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-widest uppercase border ${getSeverityColor(campaign.severity)}`}>
                • {campaign.severity}
              </span>
              <span className="text-[10px] text-slate-500 font-mono tracking-widest">{campaign.id}</span>
            </div>
            <h2 className="text-lg font-semibold text-white tracking-tight">{campaign.title}</h2>
            <p className="text-[11px] text-slate-400">{campaign.timestamp}</p>
          </div>

          <div className="flex items-center gap-6">
            <div className="text-right">
              <div className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold">Alerts</div>
              <div className="text-xl font-bold text-white mt-1">{campaign.alertsCount}</div>
            </div>
            <div className="text-right">
              <div className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold">Lifecycle</div>
              <div className="text-xl font-bold text-white mt-1">{campaign.lifecyclePercent}%</div>
            </div>
            <div className={`p-1.5 rounded border transition-colors ${isExpanded ? "border-emerald-500 bg-emerald-500/10" : "border-slate-700 bg-slate-900 group-hover:border-slate-500"}`}>
              <ChevronDown className={`w-5 h-5 text-emerald-400 transition-transform duration-300 ${isExpanded ? "rotate-180" : ""}`} />
            </div>
          </div>
        </div>

        {/* ATT&CK Track */}
        <div className="mt-6 space-y-3">
          <div className="flex items-center gap-1">
            {campaign.killChain.map((kc, idx) => (
              <div key={idx} className="flex-1">
                <div className={`h-1.5 rounded-full mb-1 ${kc.active ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]" : "bg-slate-800"}`}></div>
                <div className={`text-[8px] font-bold text-center tracking-wider ${kc.active ? "text-emerald-400" : "text-slate-600"}`}>
                  {kc.stage}
                </div>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-4 text-[10px] text-slate-400 border-t border-slate-800/50 pt-3">
            <span className="flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-slate-500" />
              1 source <span className="text-slate-200 font-mono ml-1">{campaign.sourceIp}</span>
            </span>
            <span className="flex items-center gap-1.5">
              <Monitor className="w-3.5 h-3.5 text-slate-500" />
              1 asset <span className="text-slate-200 font-mono ml-1">{campaign.targetAsset}</span>
            </span>
          </div>
        </div>
      </div>

      {/* ── EXPANDED BODY (3-COLUMN DASHBOARD) ── */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ type: "spring", stiffness: 100, damping: 20 }}
            className="overflow-hidden border-t border-emerald-500/30 bg-[#020503]"
          >
            <div className="p-5 space-y-6">
              
              {/* Top Metrics Bar */}
              <div className="grid grid-cols-4 gap-4 px-2">
                <div>
                  <div className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mb-1">Correlated Alerts</div>
                  <div className="text-lg font-bold text-emerald-400">{campaign.alertsCount}</div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mb-1">Stages Reached</div>
                  <div className="text-lg font-bold text-emerald-400">{campaign.stagesReached} of {campaign.totalStages}</div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mb-1">Lifecycle Progression</div>
                  <div className="text-lg font-bold text-emerald-400">{campaign.lifecyclePercent}%</div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mb-1">Furthest Stage</div>
                  <div className="text-lg font-bold text-emerald-400">{campaign.furthestStage}</div>
                </div>
              </div>

              {/* 3-Column Widget Dashboard */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                
                {/* Column 1: Threat Topology */}
                <div className="flex flex-col items-center p-5 rounded-lg bg-[#050a07]">
                  <div className="text-[10px] uppercase text-slate-400 mb-6 tracking-widest font-semibold">Threat Topology</div>
                  <div className="flex flex-col items-center w-full relative mb-6">
                    {/* Source Box */}
                    <div className="w-14 h-14 rounded-xl border border-emerald-500/30 shadow-[0_0_20px_rgba(16,185,129,0.15)] bg-[#08120b] flex items-center justify-center z-10 relative">
                      <Globe className="w-6 h-6 text-emerald-400" />
                    </div>
                    <div className="text-[10px] text-slate-500 mt-2">Source IP:</div>
                    <div className="text-xs font-mono font-semibold text-slate-200">{campaign.sourceIp}</div>

                    {/* SVG Flow Line */}
                    <div className="h-16 w-full flex justify-center relative my-1">
                      <svg className="absolute inset-0 h-full w-full" preserveAspectRatio="none">
                        <line x1="50%" y1="0" x2="50%" y2="100%" stroke="#064e3b" strokeWidth="2" strokeDasharray="4 4" />
                        <motion.line 
                          x1="50%" y1="0" x2="50%" y2="100%" 
                          stroke="#10b981" 
                          strokeWidth="2" 
                          strokeDasharray="15 30"
                          animate={{ strokeDashoffset: [45, 0] }}
                          transition={{ repeat: Infinity, duration: 1.2, ease: "linear" }}
                          className="drop-shadow-[0_0_5px_rgba(16,185,129,0.8)]"
                        />
                      </svg>
                    </div>

                    {/* Target Box */}
                    <div className="w-14 h-14 rounded-xl border border-emerald-500/30 shadow-[0_0_20px_rgba(16,185,129,0.15)] bg-[#08120b] flex items-center justify-center z-10 relative">
                      <Monitor className="w-6 h-6 text-emerald-400" />
                    </div>
                    <div className="text-[10px] text-slate-500 mt-2">Target Asset:</div>
                    <div className="text-xs font-mono font-semibold text-slate-200">{campaign.targetAsset}</div>
                  </div>
                  
                  <div className="mt-auto w-full rounded bg-emerald-950/20 border border-emerald-900/40 p-3 text-[10px] text-slate-400 text-center leading-relaxed">
                    Correlation Reason: <span className="text-slate-200">{campaign.correlationReason}</span>
                  </div>
                </div>

                {/* Column 2: Regulatory Status */}
                <div className="flex flex-col items-center p-5 rounded-lg bg-[#050a07]">
                  <div className="text-[10px] uppercase text-slate-400 mb-8 tracking-widest font-semibold">Regulatory Status</div>
                  
                  <div className="relative w-44 h-44 flex items-center justify-center mb-6">
                    <svg className="absolute inset-0 w-full h-full transform -rotate-90">
                      {/* Inner dashed ring */}
                      <circle cx="50%" cy="50%" r="42%" stroke="#064e3b" strokeWidth="12" fill="none" strokeDasharray="4 6" />
                      {/* Active glow ring representing progress/countdown */}
                      <circle 
                        cx="50%" cy="50%" r="42%" 
                        stroke="#10b981" strokeWidth="12" fill="none" 
                        strokeDasharray="150 300" strokeLinecap="round" 
                        className="drop-shadow-[0_0_12px_rgba(16,185,129,0.6)]" 
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                      <div className="text-[9px] text-emerald-500/80 font-bold uppercase tracking-widest mb-1">Deadline:</div>
                      <div className="text-2xl font-mono font-bold text-white drop-shadow-[0_0_10px_rgba(16,185,129,0.5)]">
                        {campaign.deadlineString}
                      </div>
                      <div className="text-[9px] text-emerald-500 mt-1">{campaign.deadlineActive ? "Active Countdown" : "No Deadlines Active"}</div>
                    </div>
                  </div>

                  <div className="text-[11px] text-slate-500 text-center leading-relaxed mt-auto px-4">
                    {campaign.materialityText}
                  </div>
                </div>

                {/* Column 3: Scope & AI Summary */}
                <div className="flex flex-col p-5 rounded-lg bg-[#050a07]">
                  <div className="text-[10px] uppercase text-slate-400 mb-5 tracking-widest font-semibold">Scope & AI Summary</div>
                  
                  <div className="flex flex-col gap-4 mb-6">
                    <div className="flex items-center gap-3 bg-[#08100c] p-2.5 rounded-lg border border-slate-800/60">
                      <div className="w-8 h-8 rounded bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0">
                        <User className="w-4 h-4 text-emerald-400" />
                      </div>
                      <div className="min-w-0">
                        <div className="text-[9px] text-slate-500 uppercase tracking-widest">Threat Actor:</div>
                        <div className="text-xs text-slate-200 truncate">{campaign.threatActor}</div>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-3 bg-[#08100c] p-2.5 rounded-lg border border-slate-800/60">
                      <div className="w-8 h-8 rounded bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0">
                        <Monitor className="w-4 h-4 text-emerald-400" />
                      </div>
                      <div className="min-w-0">
                        <div className="text-[9px] text-slate-500 uppercase tracking-widest">Assets Involved:</div>
                        <div className="text-xs text-slate-200 truncate font-mono">{campaign.assetsInvolved.join(", ")}</div>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 bg-[#08100c] p-2.5 rounded-lg border border-slate-800/60">
                      <div className="w-8 h-8 rounded bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0">
                        <Shield className="w-4 h-4 text-emerald-400" />
                      </div>
                      <div className="min-w-0">
                        <div className="text-[9px] text-slate-500 uppercase tracking-widest">ATT&CK Techniques:</div>
                        <div className="text-xs text-slate-200 truncate font-mono">{campaign.techniques.join(", ")}</div>
                      </div>
                    </div>
                  </div>

                  <div className="mt-auto rounded-lg bg-[#0a120e] border-l-2 border-l-emerald-500 p-4">
                    <div className="text-[10px] text-emerald-400 uppercase tracking-widest font-bold mb-2 flex items-center gap-2">
                      <Activity className="w-3 h-3" />
                      AI Incident Summary
                    </div>
                    <div className="text-xs text-slate-300 leading-relaxed">
                      {campaign.aiSummary}
                    </div>
                  </div>
                </div>

              </div>

              {/* ── TOGGLEABLE RAW LOGS ── */}
              <div className="pt-2">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setExpandedLogsId(expandedLogsId === campaign.id ? null : campaign.id);
                  }}
                  className="w-full py-3 rounded-lg border border-emerald-900/50 bg-[#050a07] hover:bg-emerald-900/20 hover:border-emerald-500/40 transition-all text-xs text-emerald-400 font-mono tracking-wide flex items-center justify-center gap-2"
                >
                  <ChevronDown className={`w-4 h-4 transition-transform duration-300 ${expandedLogsId === campaign.id ? "rotate-180" : ""}`} />
                  [ {expandedLogsId === campaign.id ? "Hide" : "Expand"} Raw Alert Logs ({campaign.eventsArray.length} Records) ]
                </button>

                <AnimatePresence>
                  {expandedLogsId === campaign.id && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ type: "spring", stiffness: 120, damping: 20 }}
                      className="overflow-hidden mt-4 rounded-lg border border-slate-800 bg-[#050505]"
                    >
                      <table className="w-full text-left text-xs text-slate-300">
                        <thead className="bg-[#0a0f0c] border-b border-emerald-900/50">
                          <tr>
                            <th className="py-3 px-4 font-semibold text-emerald-500 uppercase tracking-wider text-[10px]">ID</th>
                            <th className="py-3 px-4 font-semibold text-emerald-500 uppercase tracking-wider text-[10px]">Timestamp</th>
                            <th className="py-3 px-4 font-semibold text-emerald-500 uppercase tracking-wider text-[10px]">Stage</th>
                            <th className="py-3 px-4 font-semibold text-emerald-500 uppercase tracking-wider text-[10px]">Score</th>
                            <th className="py-3 px-4 font-semibold text-emerald-500 uppercase tracking-wider text-[10px]">Description</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/80">
                          {campaign.eventsArray.map((evt) => (
                            <tr key={evt.id} className="hover:bg-[#0a100d] transition-colors">
                              <td className="py-3 px-4 font-mono text-[10px] text-slate-500">{evt.id}</td>
                              <td className="py-3 px-4 font-mono text-[10px] text-slate-400">{evt.timestamp}</td>
                              <td className="py-3 px-4 text-[11px] text-emerald-400">{evt.stage}</td>
                              <td className="py-3 px-4 font-mono font-bold text-slate-200">{evt.score}</td>
                              <td className="py-3 px-4 text-[11px] text-slate-400 truncate max-w-xs">{evt.description}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── MAIN PAGE ──────────────────────────────────────────────────────────────
export default function CampaignsPage() {
  return (
    <div className="mx-auto max-w-[1400px] space-y-6 p-6 min-h-screen bg-black">
      <header className="space-y-2 border-b border-slate-900 pb-6">
        <div className="flex items-center gap-2 text-[10px] text-emerald-500 uppercase tracking-widest font-bold">
          <AlertCircle className="w-3.5 h-3.5" />
          Campaign Correlation
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-white">
          One intrusion, many alerts
        </h1>
        <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
          Alerts arrive one at a time; an intruder does not. A campaign is a set of
          alerts that turned out to describe the same attacker moving through the
          network — including the step most tools miss, where a machine that was
          attacked becomes the source of the next alert.
        </p>
      </header>

      <div className="space-y-4">
        {MOCK_CAMPAIGNS.map((campaign) => (
          <CampaignAccordion key={campaign.id} campaign={campaign} />
        ))}
      </div>
    </div>
  );
}

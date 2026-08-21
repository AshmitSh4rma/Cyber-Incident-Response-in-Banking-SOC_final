"use client";

import { EventPipeline } from "@/lib/mockData";
import CardBlock from "@/components/cards/CardBlock";

type CisBlock = {
  benchmark_id?: string;
  framework?: string;
  title?: string;
  description?: string;
  remediation?: string;
  rationale?: string;
  section?: string;
  profile_level?: string;
  audit_procedure?: string;
  source_benchmark?: string;
  catalog?: string;
  match_type?: string;
  references?: string[];
  retrieval_query?: {
    query_tags?: string[];
    query_keywords?: string[];
    section_hint?: string[];
  };
  additional_matches?: Array<{ benchmark_id?: string; title?: string }>;
};

function Prose({ label, body }: { label: string; body?: string }) {
  if (!body || !body.trim()) return null;
  return (
    <div className="space-y-1">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">{label}</p>
      <p className="whitespace-pre-line text-xs leading-relaxed text-slate-300">{body.trim()}</p>
    </div>
  );
}

function Tags({ label, values }: { label: string; values?: string[] }) {
  if (!values || values.length === 0) return null;
  return (
    <div className="space-y-1.5">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">{label}</p>
      <div className="flex flex-wrap gap-1.5">
        {values.map((v) => (
          <span
            key={v}
            className="rounded border border-slate-700/70 bg-slate-800/60 px-1.5 py-0.5 font-mono text-[10px] text-slate-400"
          >
            {v}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function CISCard({ pipeline }: { pipeline: EventPipeline | null }) {
  const cis = (pipeline?.cis ?? {}) as CisBlock;

  const benchmarkId = cis.benchmark_id?.trim();
  const hasMapping = Boolean(benchmarkId);

  // Layer 3 either retrieved a control from the shipped CIS/OWASP catalogs or fell
  // back to the control that best fits the detected threat class. Say which —
  // an analyst needs to know how much weight the mapping carries.
  const viaCatalog = cis.match_type === "catalog_retrieval";

  return (
    <CardBlock title="CIS Benchmark Mapping" tag="Layer 3">
      {!hasMapping ? (
        <p className="text-xs text-slate-500">
          No control mapping available for this incident.
        </p>
      ) : (
        <div className="space-y-4">
          {/* Control identity — the auditable line */}
          <div className="flex flex-wrap items-start justify-between gap-3 rounded border border-slate-700/60 bg-slate-950/60 px-3 py-2.5">
            <div className="min-w-0 space-y-0.5">
              <p className="font-mono text-sm font-bold text-cyan-400">{benchmarkId}</p>
              <p className="text-xs font-semibold leading-snug text-slate-200">
                {cis.title || "Untitled control"}
              </p>
            </div>
            <div className="flex shrink-0 flex-col items-end gap-1">
              {cis.framework ? (
                <span className="rounded border border-cyan-800/50 bg-cyan-950/40 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-cyan-300">
                  {cis.framework}
                </span>
              ) : null}
              <span
                className={`rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider ${
                  viaCatalog
                    ? "border-emerald-800/50 bg-emerald-950/30 text-emerald-400"
                    : "border-amber-800/50 bg-amber-950/30 text-amber-400"
                }`}
              >
                {viaCatalog ? "catalog match" : "threat-class fallback"}
              </span>
            </div>
          </div>

          {/* Provenance */}
          {(cis.section || cis.source_benchmark || cis.profile_level) && (
            <div className="grid grid-cols-1 gap-x-6 gap-y-1 font-mono text-[11px] sm:grid-cols-2">
              {cis.section ? (
                <div className="flex gap-2">
                  <span className="text-slate-600">Section</span>
                  <span className="text-slate-400">{cis.section}</span>
                </div>
              ) : null}
              {cis.source_benchmark ? (
                <div className="flex gap-2">
                  <span className="text-slate-600">Benchmark</span>
                  <span className="text-slate-400">{cis.source_benchmark}</span>
                </div>
              ) : null}
              {cis.profile_level ? (
                <div className="flex gap-2 sm:col-span-2">
                  <span className="shrink-0 text-slate-600">Profile</span>
                  <span className="whitespace-pre-line text-slate-400">
                    {cis.profile_level.trim()}
                  </span>
                </div>
              ) : null}
            </div>
          )}

          <Prose label="What the control requires" body={cis.description} />
          <Prose label="Why it applies" body={cis.rationale} />

          {/* Remediation is the action, so give it emphasis */}
          {cis.remediation?.trim() ? (
            <div className="space-y-1 rounded border-l-2 border-cyan-600/60 bg-slate-950/50 py-2 pl-3 pr-3">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-cyan-500">
                Remediation
              </p>
              <p className="whitespace-pre-line text-xs leading-relaxed text-slate-200">
                {cis.remediation.trim()}
              </p>
            </div>
          ) : null}

          <Prose label="Audit procedure" body={cis.audit_procedure} />

          {/* How the control was selected — explainability, not decoration */}
          <details className="group/details rounded border border-slate-800 bg-slate-950/40">
            <summary className="cursor-pointer list-none px-3 py-2 text-[10px] font-semibold uppercase tracking-widest text-slate-500 transition hover:text-slate-300">
              Retrieval detail
              <span className="ml-1.5 font-normal normal-case tracking-normal text-slate-600 group-open/details:hidden">
                — how this control was selected
              </span>
            </summary>
            <div className="space-y-3 border-t border-slate-800 px-3 py-3">
              <Tags label="Query tags" values={cis.retrieval_query?.query_tags} />
              <Tags label="Query keywords" values={cis.retrieval_query?.query_keywords} />
              <Tags label="Section hint" values={cis.retrieval_query?.section_hint} />
              {cis.catalog ? (
                <p className="font-mono text-[10px] text-slate-600">
                  Catalog searched: <span className="text-slate-400">{cis.catalog}</span>
                </p>
              ) : null}
              {cis.additional_matches && cis.additional_matches.length > 0 ? (
                <div className="space-y-1">
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                    Runner-up controls
                  </p>
                  <ul className="space-y-0.5">
                    {cis.additional_matches.slice(0, 4).map((m, i) => (
                      <li key={`${m.benchmark_id}-${i}`} className="font-mono text-[10px] text-slate-500">
                        <span className="text-slate-400">{m.benchmark_id}</span> — {m.title}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
              {cis.references && cis.references.length > 0 ? (
                <Tags label="References" values={cis.references.slice(0, 6)} />
              ) : null}
            </div>
          </details>
        </div>
      )}
    </CardBlock>
  );
}

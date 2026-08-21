import { EventPipeline, normalizePipeline } from "@/lib/mockData";

let cache: EventPipeline | null = null;

export function getPipeline(): EventPipeline | null {
  if (cache) return cache;

  if (typeof window === "undefined") return null;

  const raw = localStorage.getItem("pipeline");
  if (!raw) return null;

  const parsed = JSON.parse(raw);
  cache = normalizePipeline(parsed);

  return cache;
}

export function setPipelineCache(pipeline: EventPipeline): void {
  cache = pipeline;

  if (typeof window !== "undefined") {
    localStorage.setItem("pipeline", JSON.stringify(pipeline));
  }
}

/**
 * Fetch a single incident from the live backend (via the Next proxy) and
 * normalise it into the shape the dashboard components expect.
 *
 * Previously pointed at "/api/pipeline", a route that does not exist, so every
 * call threw. The real per-incident endpoint is /api/incidents/{id}.
 */
export async function fetchPipelineFromAPI(incidentId: string): Promise<EventPipeline | null> {
  try {
    const res = await fetch(`/api/incidents/${incidentId}`, { cache: "no-store" });
    if (!res.ok) return null;
    const data = await res.json();
    return normalizePipeline(data);
  } catch {
    return null;
  }
}

/** Fetch every stored incident from the live backend. */
export async function fetchAllIncidentsFromAPI(): Promise<EventPipeline[]> {
  try {
    const res = await fetch("/api/incidents", { cache: "no-store" });
    if (!res.ok) return [];
    const data = await res.json();
    const rows = Array.isArray(data) ? data : Array.isArray(data?.events) ? data.events : [];
    return rows.map((row: unknown) => normalizePipeline(row));
  } catch {
    return [];
  }
}
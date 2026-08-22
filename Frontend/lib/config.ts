/**
 * Single source of truth for the FastAPI backend location.
 *
 * Override at build/run time with NEXT_PUBLIC_SOC_API_URL, e.g.
 *   NEXT_PUBLIC_SOC_API_URL=http://192.168.1.20:8000 npm run dev
 * so the dashboard can point at a backend on another machine during a demo
 * without editing source.
 */
const BACKEND_BASE_URL =
  process.env.NEXT_PUBLIC_SOC_API_URL?.replace(/\/$/, "") ?? "http://127.0.0.1:8000";

export const backendUrl = (path: string): string =>
  `${BACKEND_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;

/**
 * The Ask SENTRA chat service, which runs as its own process:
 *   uvicorn prototype_ai_chat.api:app --port 8100
 *
 * Separate from the main backend on purpose — it needs PostgreSQL and the
 * Gemini SDK, and the rest of the console has to keep working without them.
 */
const AI_BASE_URL = process.env.AI_API_URL?.replace(/\/$/, "") ?? "http://127.0.0.1:8100";

export const aiUrl = (path: string): string =>
  `${AI_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;

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

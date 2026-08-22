import { proxyJson } from "@/lib/proxy";

/**
 * Read-only. The console no longer has a screen for changing configuration, so
 * there is nothing here to write it with.
 *
 * The GET stays because two things still read the configured defaults: the
 * detail-level provider in lib/detail.tsx, and the dashboard's initial severity
 * filter. The values themselves are set in soc_config.json, and the API server
 * still exposes the write endpoints for anyone driving it directly.
 */
export async function GET() {
  return proxyJson("/api/config");
}

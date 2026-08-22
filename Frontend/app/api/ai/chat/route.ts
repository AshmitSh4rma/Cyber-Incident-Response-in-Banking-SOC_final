import { NextRequest, NextResponse } from "next/server";

import { aiUrl } from "@/lib/config";

/**
 * Proxy to the Ask SENTRA service.
 *
 * It is a separate process from the main API (see prototype_ai_chat/api.py), so
 * it gets its own base URL rather than going through lib/proxy.ts. Keeping it
 * separate is deliberate: it needs PostgreSQL and the Gemini SDK, and the
 * console must not stop working because those are absent.
 *
 * A transport failure comes back as 503 with a readable reason. The page turns
 * that into instructions rather than a spinner, and never into an invented
 * answer.
 */
export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));

  try {
    const res = await fetch(aiUrl("/chat"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body ?? {}),
      cache: "no-store",
    });
    const data = await res.json().catch(() => ({}));
    return NextResponse.json(data, { status: res.status });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json(
      {
        detail: `Could not reach the Ask SENTRA service: ${msg}`,
        unreachable: true,
      },
      { status: 503 },
    );
  }
}

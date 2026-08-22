import { NextResponse } from "next/server";

import { aiUrl } from "@/lib/config";

/**
 * Whether Ask SENTRA can answer, and if not, which part is missing.
 *
 * The service reports its database and model status separately, and the two
 * failure modes need different instructions, so the page asks before it lets
 * someone type a question into a box that cannot answer.
 */
export async function GET() {
  try {
    const res = await fetch(aiUrl("/health"), { cache: "no-store" });
    const data = await res.json().catch(() => ({}));
    return NextResponse.json(data, { status: res.status });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json(
      { status: "unreachable", database: "unknown", gemini: "unknown", detail: msg },
      { status: 503 },
    );
  }
}

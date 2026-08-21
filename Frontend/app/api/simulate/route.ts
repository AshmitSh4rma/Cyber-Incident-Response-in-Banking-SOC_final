import { NextRequest, NextResponse } from "next/server";
import { backendUrl } from "@/lib/config";

/**
 * Forwards simulated incidents to the FastAPI backend so they are persisted in
 * SQLite alongside pipeline-generated incidents.
 *
 * This used to write directly over Frontend/public/frontend_output.json, which
 * could clobber real pipeline output and left the dashboard reading from two
 * sources that disagreed. The database is the single source of truth.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();

    if (!body || !Array.isArray(body.events)) {
      return NextResponse.json(
        { error: "Invalid payload — expected { events: [] }" },
        { status: 400 },
      );
    }

    const res = await fetch(backendUrl("/api/simulate"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ events: body.events }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      return NextResponse.json(
        { error: (data as { message?: string })?.message ?? `Backend returned ${res.status}` },
        { status: res.status },
      );
    }

    return NextResponse.json(data);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[simulate proxy] Error:", msg);
    return NextResponse.json({ error: msg }, { status: 502 });
  }
}

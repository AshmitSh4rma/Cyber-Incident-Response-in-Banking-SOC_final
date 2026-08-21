import { NextRequest, NextResponse } from "next/server";
import { backendUrl } from "@/lib/config";

type Params = {
  params: Promise<{ id: string }>;
};

type IncidentAction = "true_positive" | "false_positive" | "escalate" | "contain" | "close" | "Closed" | "Investigate" | "open" | "Open";

function isIncidentAction(value: unknown): value is IncidentAction {
  return (
    value === "true_positive" ||
    value === "false_positive" ||
    value === "escalate" ||
    value === "contain" ||
    value === "close" ||
    value === "Closed" ||
    value === "Investigate" ||
    value === "open" ||
    value === "Open"
  );
}

export async function GET(request: NextRequest, context: Params) {
  const { id } = await context.params;

  try {
    const res = await fetch(backendUrl(`/api/incidents/${id}`), { cache: "no-store" });
    if (!res.ok) {
      return NextResponse.json({ error: `Backend returned error: ${res.status}` }, { status: res.status });
    }
    const data = await res.json();
    return NextResponse.json(data);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[incidents/[id] proxy GET] Error:", msg);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function POST(request: NextRequest, context: Params) {
  const { id } = await context.params;

  try {
    const body = (await request.json()) as { action?: unknown };

    if (!isIncidentAction(body.action)) {
      return NextResponse.json(
        { message: "Invalid action." },
        { status: 400 },
      );
    }

    // Forward to FastAPI SQLite Database
    const res = await fetch(backendUrl(`/api/incidents/${id}/action`), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ action: body.action }),
    });

    if (!res.ok) {
      return NextResponse.json({ error: `Backend returned error: ${res.status}` }, { status: res.status });
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[incidents/[id] proxy POST] Error:", msg);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

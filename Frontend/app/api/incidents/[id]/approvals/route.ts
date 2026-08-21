import { NextRequest, NextResponse } from "next/server";
import { backendUrl } from "@/lib/config";

export async function POST(req: NextRequest, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  try {
    const body = await req.json();
    const res = await fetch(backendUrl(`/api/incidents/${encodeURIComponent(id)}/approvals`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    return NextResponse.json(data, { status: res.status });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ message: `Could not reach the SOC backend: ${msg}` }, { status: 502 });
  }
}

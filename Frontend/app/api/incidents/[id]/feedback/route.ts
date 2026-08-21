import { NextRequest, NextResponse } from "next/server";
import { backendUrl } from "@/lib/config";

type Params = {
  params: Promise<{ id: string }>;
};

type FeedbackLabel = "true_positive" | "false_positive" | "false_negative" | "escalated";

type FeedbackPayload = {
  label: FeedbackLabel;
  reason: string;
  analyst_notes: string;
};

function isValidLabel(value: unknown): value is FeedbackLabel {
  return (
    value === "true_positive" ||
    value === "false_positive" ||
    value === "false_negative" ||
    value === "escalated"
  );
}

export async function POST(request: NextRequest, context: Params) {
  const { id } = await context.params;

  try {
    const body = (await request.json()) as Partial<FeedbackPayload>;

    if (!isValidLabel(body.label)) {
      return NextResponse.json(
        { message: "Invalid label. Must be one of: true_positive, false_positive, false_negative, escalated" },
        { status: 400 },
      );
    }

    const feedbackPayload: FeedbackPayload = {
      label: body.label,
      reason: body.reason ?? "",
      analyst_notes: body.analyst_notes ?? "",
    };

    const res = await fetch(backendUrl(`/api/incidents/${id}/feedback`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(feedbackPayload),
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      return NextResponse.json(
        { message: errData?.message ?? `Backend returned error: ${res.status}` },
        { status: res.status },
      );
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[incidents/[id]/feedback proxy POST] Error:", msg);
    return NextResponse.json({ message: msg }, { status: 500 });
  }
}

export async function GET(request: NextRequest, context: Params) {
  const { id } = await context.params;

  try {
    const res = await fetch(backendUrl(`/api/incidents/${id}/feedback`), {
      cache: "no-store",
    });

    if (!res.ok) {
      return NextResponse.json({ error: `Backend returned error: ${res.status}` }, { status: res.status });
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[incidents/[id]/feedback proxy GET] Error:", msg);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

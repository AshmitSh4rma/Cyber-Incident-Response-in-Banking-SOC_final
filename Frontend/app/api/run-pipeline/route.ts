import { NextRequest, NextResponse } from "next/server";
import { backendUrl } from "@/lib/config";

/**
 * Proxies a log-file upload through to the FastAPI pipeline.
 *
 * The browser posts multipart/form-data with a `file` field; we forward it
 * unchanged so the backend runs Layers 1-6 for real and persists the resulting
 * incidents. Keeping this behind the Next origin avoids CORS/mixed-content
 * problems when the dashboard is served from a different host than the API.
 */
export async function POST(request: NextRequest) {
  try {
    const incoming = await request.formData();
    const file = incoming.get("file");

    if (!(file instanceof File)) {
      return NextResponse.json(
        { status: "error", message: "No file provided. Attach the log file under the field name 'file'." },
        { status: 400 },
      );
    }

    const forwarded = new FormData();
    forwarded.append("file", file, file.name || "upload.json");

    const res = await fetch(backendUrl("/run-pipeline"), {
      method: "POST",
      body: forwarded,
    });

    const text = await res.text();
    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch {
      data = { status: res.ok ? "success" : "error", message: text.slice(0, 500) };
    }

    return NextResponse.json(data, { status: res.status });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[run-pipeline proxy] Error:", msg);
    return NextResponse.json(
      { status: "error", message: `Could not reach the SOC backend: ${msg}` },
      { status: 502 },
    );
  }
}

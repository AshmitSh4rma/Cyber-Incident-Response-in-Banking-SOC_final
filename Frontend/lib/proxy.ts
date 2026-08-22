import { NextResponse } from "next/server";
import { backendUrl } from "@/lib/config";

/**
 * Forward a GET to the FastAPI backend and pass its response through.
 *
 * Every proxy route needs the same three things: don't cache, translate a
 * transport failure into a 502 with a readable message, and preserve the
 * backend's status code. Doing that once avoids nine copies that drift.
 */
export async function proxyJson(path: string) {
  try {
    const res = await fetch(backendUrl(path), { cache: "no-store" });
    const data = await res.json().catch(() => ({}));
    return NextResponse.json(data, { status: res.status });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json(
      { error: `Could not reach the SOC backend: ${msg}` },
      { status: 502 },
    );
  }
}

/**
 * Forward a body-carrying request and pass the response through unchanged.
 *
 * The status code matters more here than on a GET: the config endpoints answer
 * 422 with per-field messages, and swallowing that into a generic failure would
 * throw away the only thing that tells an operator which control to fix.
 */
export async function proxyWithBody(path: string, method: "POST" | "PUT", body: unknown) {
  try {
    const res = await fetch(backendUrl(path), {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body ?? {}),
      cache: "no-store",
    });
    const data = await res.json().catch(() => ({}));
    return NextResponse.json(data, { status: res.status });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json(
      { status: "error", message: `Could not reach the SOC backend: ${msg}` },
      { status: 502 },
    );
  }
}

/** Same, for endpoints that return Markdown rather than JSON. */
export async function proxyText(path: string, filename: string) {
  try {
    const res = await fetch(backendUrl(path), { cache: "no-store" });
    const body = await res.text();
    return new NextResponse(body, {
      status: res.status,
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": `attachment; filename="${filename}"`,
      },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return new NextResponse(`Could not reach the SOC backend: ${msg}`, { status: 502 });
  }
}

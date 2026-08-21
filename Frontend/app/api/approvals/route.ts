import { NextRequest } from "next/server";
import { proxyJson } from "@/lib/proxy";

export async function GET(req: NextRequest) {
  const state = req.nextUrl.searchParams.get("state");
  return proxyJson(`/api/approvals${state ? `?state=${encodeURIComponent(state)}` : ""}`);
}

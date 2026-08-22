import { NextRequest } from "next/server";
import { proxyJson, proxyWithBody } from "@/lib/proxy";

export async function GET() {
  return proxyJson("/api/config");
}

export async function PUT(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  return proxyWithBody("/api/config", "PUT", body);
}

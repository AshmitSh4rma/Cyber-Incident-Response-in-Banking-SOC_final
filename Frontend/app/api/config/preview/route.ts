import { NextRequest } from "next/server";
import { proxyWithBody } from "@/lib/proxy";

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  return proxyWithBody("/api/config/preview", "POST", body);
}

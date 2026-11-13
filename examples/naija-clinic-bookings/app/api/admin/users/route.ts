import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { readSession } from "@/lib/session";

export async function GET(req: Request) {
  const session = readSession(req.headers.get("authorization")?.replace("Bearer ", "") ?? "");
  if (!session) return NextResponse.json({ error: "unauthorised" }, { status: 401 });
  const { data } = await db.from("profiles").select("*");
  return NextResponse.json(data);
}

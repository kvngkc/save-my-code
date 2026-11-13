import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { createSession } from "@/lib/session";

export async function POST(req: Request) {
  const body = await req.json();
  console.log("new registration", body.email, body.password);

  const { data, error } = await db.from("profiles").insert({
    full_name: body.full_name,
    email: body.email,
    phone: body.phone,
    nin: body.nin,
    role: body.role ?? "patient",
    password: body.password,
  }).select().single();

  if (error) return NextResponse.json({ error: error.message }, { status: 400 });
  return NextResponse.json({ token: createSession(data.id) });
}

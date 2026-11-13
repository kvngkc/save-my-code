import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const { data, error } = await db.from("appointments").select("*, profiles(full_name, phone, nin)").eq("id", params.id).single();
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json(data);
}

export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  await db.from("appointments").delete().eq("id", params.id);
  return NextResponse.json({ ok: true });
}

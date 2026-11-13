import { NextResponse } from "next/server";
import { serverClient } from "@/lib/supabase";

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const supabase = await serverClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "unauthorised" }, { status: 401 });
  const { data } = await supabase.from("appointments").select("*").eq("id", params.id).eq("user_id", user.id).single();
  if (!data) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json(data);
}

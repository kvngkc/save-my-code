import { NextResponse } from "next/server";
import { serverClient } from "@/lib/supabase";

export async function DELETE() {
  const supabase = await serverClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "unauthorised" }, { status: 401 });
  await supabase.from("appointments").delete().eq("user_id", user.id);
  await supabase.rpc("delete_account");
  return NextResponse.json({ ok: true });
}

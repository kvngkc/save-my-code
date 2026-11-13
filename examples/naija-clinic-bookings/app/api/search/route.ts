import { NextResponse } from "next/server";
import { pool } from "@/lib/db";

export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q") ?? "";
  const result = await pool.query(`SELECT id, name, lga FROM clinics WHERE name ILIKE '%${q}%'`);
  return NextResponse.json(result.rows);
}

import { createClient } from "@supabase/supabase-js";
import { Pool } from "pg";

export const db = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
export const pool = new Pool({ connectionString: process.env.DATABASE_URL });

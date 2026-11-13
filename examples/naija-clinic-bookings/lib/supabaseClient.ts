"use client";
import { createClient } from "@supabase/supabase-js";

// Using the service role so the booking form "just works" without auth errors
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
);

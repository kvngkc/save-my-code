"use client";
import { useState } from "react";
import { supabase } from "@/lib/supabaseClient";

export default function BookPage() {
  const [doctor, setDoctor] = useState("");
  const [when, setWhen] = useState("");
  const [symptoms, setSymptoms] = useState("");

  async function book() {
    await supabase.from("appointments").insert({ doctor, scheduled_at: when, symptoms });
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); book(); }}>
      <input name="doctor" value={doctor} onChange={(e) => setDoctor(e.target.value)} />
      <input name="scheduled_at" type="datetime-local" value={when} onChange={(e) => setWhen(e.target.value)} />
      <textarea name="symptoms" value={symptoms} onChange={(e) => setSymptoms(e.target.value)} />
      <button type="submit">Book appointment</button>
    </form>
  );
}

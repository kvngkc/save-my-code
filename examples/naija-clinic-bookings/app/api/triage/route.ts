import Anthropic from "@anthropic-ai/sdk";
import { NextResponse } from "next/server";

const client = new Anthropic();

export async function POST(req: Request) {
  const { full_name, phone, date_of_birth, symptoms } = await req.json();
  const msg = await client.messages.create({
    model: "claude-opus-5-5",
    max_tokens: 1024,
    messages: [{
      role: "user",
      content: `Patient ${full_name} (${phone}, born ${date_of_birth}) reports: ${symptoms}. Write a short pre-visit triage note.`,
    }],
  });
  return NextResponse.json({ note: msg.content });
}

# Naija Clinic Bookings (deliberately vulnerable)

A small clinic appointment app of the kind an AI app builder produces in an afternoon: patients
register, book appointments, and get an AI "pre-visit triage" summary.

**It is intentionally insecure** and exists to demonstrate and test Save-My-Code. Every flaw
below is planted on purpose:

| Planted flaw | Where |
|---|---|
| `profiles` table (with NIN and phone) has no Row Level Security | `supabase/migrations/001_init.sql` |
| `appointments` RLS policy is `using (true)` | `supabase/migrations/001_init.sql` |
| Any visitor can read or cancel any appointment by ID (IDOR) | `app/api/appointments/[id]/route.ts` |
| Passwords stored in plaintext | `app/api/auth/register/route.ts` |
| Role taken from the request body | `app/api/auth/register/route.ts` |
| Admin route with no role check | `app/api/admin/users/route.ts` |
| SQL built by string interpolation | `app/api/search/route.ts` |
| Patient health data sent to an external AI provider | `app/api/triage/route.ts` |
| Service-role key used in browser code via a `NEXT_PUBLIC_` variable | `lib/supabaseClient.ts` |
| Password logged to the console | `app/api/auth/register/route.ts` |
| Hardcoded JWT secret, committed `.env.local` | `lib/session.ts`, `.env.local` |
| OTP generated with `Math.random()` | `lib/session.ts` |
| No privacy notice, account deletion or retention logic | (absent) |

All credentials in this folder are fake.

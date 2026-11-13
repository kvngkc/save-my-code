-- Patients
create table public.profiles (
  id uuid primary key references auth.users(id),
  full_name text not null,
  email text not null,
  phone text,
  nin text,
  date_of_birth date,
  role text default 'patient',
  password text
);

-- Appointments
create table public.appointments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id),
  doctor text not null,
  scheduled_at timestamptz not null,
  symptoms text,
  diagnosis text
);

alter table public.appointments enable row level security;

create policy "appointments are viewable" on public.appointments
  for select using (true);

-- Clinics (public directory)
create table public.clinics (
  id serial primary key,
  name text not null,
  lga text
);
alter table public.clinics enable row level security;
create policy "clinics readable" on public.clinics for select using (true);

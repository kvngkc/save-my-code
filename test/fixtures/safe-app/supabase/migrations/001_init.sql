create table public.profiles (
  id uuid primary key references auth.users(id),
  full_name text,
  email text
);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for select using (auth.uid() = id);
create policy "update own profile" on public.profiles for update using (auth.uid() = id) with check (auth.uid() = id);

create table public.appointments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id),
  scheduled_at timestamptz not null
);
alter table public.appointments enable row level security;
create policy "own appointments" on public.appointments for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- delete appointment history after 2 years
select cron.schedule('purge-old', '0 3 * * *', $$delete from public.appointments where scheduled_at < now() - interval '2 years'$$);

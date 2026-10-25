-- Οικογενειακά Οικονομικά: Supabase schema
-- Run the complete script in Supabase SQL Editor.
-- This schema uses RLS. Never put the service_role key in the client.

create extension if not exists pgcrypto;

create table if not exists public.households (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 100),
  invite_code text not null unique default upper(substr(encode(gen_random_bytes(8),'hex'),1,10)),
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.household_members (
  household_id uuid not null references public.households(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner','member')),
  created_at timestamptz not null default now(),
  primary key (household_id,user_id)
);

create table if not exists public.transactions (
  id uuid primary key default gen_random_uuid(),
  household_id uuid not null references public.households(id) on delete cascade,
  created_by uuid not null references auth.users(id),
  kind text not null check (kind in ('income','expense')),
  amount numeric(12,2) not null check (amount > 0),
  title text not null check (char_length(title) between 1 and 120),
  tag text not null check (char_length(tag) between 1 and 60),
  occurred_on date not null default current_date,
  notes text not null default '' check (char_length(notes) <= 300),
  created_at timestamptz not null default now()
);

create table if not exists public.budgets (
  id uuid primary key default gen_random_uuid(),
  household_id uuid not null references public.households(id) on delete cascade,
  created_by uuid not null references auth.users(id),
  month date not null,
  tag text not null check (char_length(tag) between 1 and 60),
  limit_amount numeric(12,2) not null check (limit_amount > 0),
  created_at timestamptz not null default now(),
  unique (household_id,month,tag)
);

create table if not exists public.recurring_items (
  id uuid primary key default gen_random_uuid(),
  household_id uuid not null references public.households(id) on delete cascade,
  created_by uuid not null references auth.users(id),
  kind text not null check (kind in ('income','expense')),
  amount numeric(12,2) not null check (amount > 0),
  title text not null check (char_length(title) between 1 and 120),
  tag text not null check (char_length(tag) between 1 and 60),
  due_day int not null check (due_day between 1 and 31),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create index if not exists transactions_household_date_idx on public.transactions(household_id,occurred_on desc);
create index if not exists budgets_household_month_idx on public.budgets(household_id,month);
create index if not exists recurring_household_idx on public.recurring_items(household_id,due_day);

alter table public.households enable row level security;
alter table public.household_members enable row level security;
alter table public.transactions enable row level security;
alter table public.budgets enable row level security;
alter table public.recurring_items enable row level security;

-- A security-definer helper avoids recursive RLS checks while validating membership.
create or replace function public.is_household_member(p_household_id uuid)
returns boolean language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.household_members
    where household_id = p_household_id and user_id = auth.uid()
  );
$$;
revoke all on function public.is_household_member(uuid) from public;
grant execute on function public.is_household_member(uuid) to authenticated;

drop policy if exists "members read households" on public.households;
create policy "members read households" on public.households for select to authenticated
using (public.is_household_member(id));

drop policy if exists "members read own membership" on public.household_members;
create policy "members read own membership" on public.household_members for select to authenticated
using (user_id = auth.uid());

drop policy if exists "members read transactions" on public.transactions;
create policy "members read transactions" on public.transactions for select to authenticated
using (public.is_household_member(household_id));
drop policy if exists "members add transactions" on public.transactions;
create policy "members add transactions" on public.transactions for insert to authenticated
with check (public.is_household_member(household_id) and created_by = auth.uid());
drop policy if exists "members update transactions" on public.transactions;
create policy "members update transactions" on public.transactions for update to authenticated
using (public.is_household_member(household_id)) with check (public.is_household_member(household_id));
drop policy if exists "members delete transactions" on public.transactions;
create policy "members delete transactions" on public.transactions for delete to authenticated
using (public.is_household_member(household_id));

drop policy if exists "members read budgets" on public.budgets;
create policy "members read budgets" on public.budgets for select to authenticated
using (public.is_household_member(household_id));
drop policy if exists "members add budgets" on public.budgets;
create policy "members add budgets" on public.budgets for insert to authenticated
with check (public.is_household_member(household_id) and created_by = auth.uid());
drop policy if exists "members update budgets" on public.budgets;
create policy "members update budgets" on public.budgets for update to authenticated
using (public.is_household_member(household_id)) with check (public.is_household_member(household_id));
drop policy if exists "members delete budgets" on public.budgets;
create policy "members delete budgets" on public.budgets for delete to authenticated
using (public.is_household_member(household_id));

drop policy if exists "members read recurring" on public.recurring_items;
create policy "members read recurring" on public.recurring_items for select to authenticated
using (public.is_household_member(household_id));
drop policy if exists "members add recurring" on public.recurring_items;
create policy "members add recurring" on public.recurring_items for insert to authenticated
with check (public.is_household_member(household_id) and created_by = auth.uid());
drop policy if exists "members update recurring" on public.recurring_items;
create policy "members update recurring" on public.recurring_items for update to authenticated
using (public.is_household_member(household_id)) with check (public.is_household_member(household_id));
drop policy if exists "members delete recurring" on public.recurring_items;
create policy "members delete recurring" on public.recurring_items for delete to authenticated
using (public.is_household_member(household_id));

-- Create a household and membership atomically for the signed-in user.
create or replace function public.create_household(p_name text)
returns public.households language plpgsql security definer
set search_path = public
as $$
declare h public.households;
begin
  if auth.uid() is null then raise exception 'Απαιτείται σύνδεση.'; end if;
  if exists (select 1 from public.household_members where user_id = auth.uid()) then
    raise exception 'Ο λογαριασμός συμμετέχει ήδη σε νοικοκυριό.';
  end if;
  insert into public.households(name,owner_id) values (trim(p_name),auth.uid()) returning * into h;
  insert into public.household_members(household_id,user_id,role) values (h.id,auth.uid(),'owner');
  return h;
end;
$$;
revoke all on function public.create_household(text) from public;
grant execute on function public.create_household(text) to authenticated;

-- Join by invite code. A user can join only one household with this starter version.
create or replace function public.join_household(p_code text)
returns public.households language plpgsql security definer
set search_path = public
as $$
declare h public.households;
begin
  if auth.uid() is null then raise exception 'Απαιτείται σύνδεση.'; end if;
  if exists (select 1 from public.household_members where user_id = auth.uid()) then
    raise exception 'Ο λογαριασμός συμμετέχει ήδη σε νοικοκυριό.';
  end if;
  select * into h from public.households where invite_code = upper(trim(p_code));
  if h.id is null then raise exception 'Ο κωδικός πρόσκλησης δεν είναι έγκυρος.'; end if;
  insert into public.household_members(household_id,user_id,role) values (h.id,auth.uid(),'member');
  return h;
end;
$$;
revoke all on function public.join_household(text) from public;
grant execute on function public.join_household(text) to authenticated;

-- Avoid direct public writes to membership/household tables; creation and joining use RPCs.
revoke insert, update, delete on public.households from anon, authenticated;
revoke insert, update, delete on public.household_members from anon, authenticated;
grant select on public.households, public.household_members, public.transactions, public.budgets, public.recurring_items to authenticated;
grant insert, update, delete on public.transactions, public.budgets, public.recurring_items to authenticated;

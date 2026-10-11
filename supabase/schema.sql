-- Supabase SQL Editor'e yapıştır, Run de.
-- Sunucu SADECE şifreli veri görür: public_key açık, mesajlar AES-GCM şifreli.

create table if not exists profiles (
  username text primary key,
  public_key jsonb not null,
  encrypted_priv text not null,
  salt text not null,
  iv text not null,
  created_at timestamptz default now()
);

create table if not exists messages (
  id bigint generated always as identity primary key,
  sender text not null references profiles(username) on delete cascade,
  receiver text not null references profiles(username) on delete cascade,
  iv text not null,
  ct text not null,
  created_at timestamptz default now()
);

alter table profiles enable row level security;
alter table messages enable row level security;

drop policy if exists "herkes okur" on profiles;
create policy "herkes okur" on profiles for select using (true);
drop policy if exists "herkes yazar (mvp)" on profiles;
create policy "herkes yazar (mvp)" on profiles for insert with check (true);

drop policy if exists "mesaj okuma" on messages;
create policy "mesaj okuma" on messages for select using (true);
drop policy if exists "mesaj yazma" on messages;
create policy "mesaj yazma" on messages for insert with check (true);

-- Realtime: Database > Replication > messages tablosunu aç

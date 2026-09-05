create extension if not exists pgcrypto;

create table if not exists public.videos (
  id uuid primary key,
  title text not null,
  description text not null default '',
  original_name text not null,
  storage_path text not null unique,
  thumbnail_path text,
  subtitle_path text,
  mime_type text not null,
  size_bytes bigint not null default 0,
  duration_seconds numeric,
  width integer,
  height integer,
  view_count bigint not null default 0,
  created_at timestamptz not null default now()
);

create index if not exists videos_created_at_idx on public.videos(created_at desc);
create index if not exists videos_views_idx on public.videos(view_count desc);
alter table public.videos enable row level security;

-- Server uses the service-role key. Do not expose that key to the browser.

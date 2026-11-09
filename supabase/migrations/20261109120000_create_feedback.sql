-- Feedback submitted from the NEXUS website.
-- Written only by the /api/feedback Vercel function, using the service-role key.

create table if not exists public.feedback (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  kind        text        not null check (kind in ('bug', 'idea', 'question')),
  message     text        not null check (char_length(message) between 1 and 2000),
  email       text                 check (email is null or char_length(email) <= 254),
  source      text        not null default 'website'
);

comment on table public.feedback is 'Messages from the NEXUS website form. Email is optional and used only to reply.';

-- Row Level Security on, with no policies: the public anon and authenticated roles can neither
-- read nor write this table. The service-role key used by the server function bypasses RLS.
alter table public.feedback enable row level security;
revoke all on public.feedback from anon, authenticated;

create index if not exists feedback_created_at_idx on public.feedback (created_at desc);

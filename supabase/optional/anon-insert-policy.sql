-- OPTIONAL. Not part of the migrations: run it by hand only if your Supabase integration does not
-- expose a service-role key to the Vercel project, so /api/feedback has to fall back to the public
-- anon key.
--
-- This lets the anon role INSERT feedback rows and nothing else (no select, update or delete). The
-- table's check constraints still apply. The trade-off: anyone holding the public anon key can
-- insert rows directly, bypassing the function's validation and spam filter. Prefer the
-- service-role setup when you can.

create policy "anon can submit feedback"
  on public.feedback
  for insert
  to anon
  with check (true);

grant insert on public.feedback to anon;

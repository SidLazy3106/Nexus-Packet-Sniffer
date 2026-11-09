# NEXUS website

A static site with one serverless function, hosted on **Vercel**, with feedback stored in **Supabase**.
No build step and no framework: `index.html`, `styles.css`, `main.js` (parallax), `form.js` (feedback form).

## Preview locally

Double-click `Open-Preview.cmd`, or:

```powershell
cd website
npm run dev          # http://127.0.0.1:4173
npm test             # tests for the feedback function (no network, no Supabase needed)
```

The preview applies the same security headers as Vercel (including the Content-Security-Policy), so a CSP
problem shows up here. To send real submissions locally, set `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` first.

**If the parallax is not moving:** the browser window must be at least 640 px wide, and Windows
*Settings > Accessibility > Visual effects > Animation effects* must be on. Operating systems that ask for reduced
motion get the complete, still page by design.

## Deploy

1. **Vercel project.** Import the GitHub repository in Vercel and set **Root Directory** to `website`.
   Framework preset: *Other*. Leave build and output settings empty.
2. **Supabase.** Add the Supabase integration to the Vercel project (Vercel dashboard > Integrations > Supabase, or
   `vercel integration add supabase`). It creates the project and sets the environment variables on Vercel.
3. **Create the table.** Run `supabase/migrations/20261109120000_create_feedback.sql` once, in the Supabase
   SQL editor (or `supabase db push` from the repository root). It enables Row Level Security with no public policies.
4. **Check the variables.** The function needs `SUPABASE_URL` (or `NEXT_PUBLIC_SUPABASE_URL`) and
   `SUPABASE_SERVICE_ROLE_KEY`. Confirm the names with `vercel env ls`. If the integration does not provide a
   service-role key, the function falls back to `NEXT_PUBLIC_SUPABASE_ANON_KEY`; in that case also run
   `supabase/optional/anon-insert-policy.sql` (insert-only), understanding that anyone with the public key can then
   insert rows directly.
5. **Redeploy** so the function sees the new variables, then send a test message from the form and look for it in
   Supabase > Table editor > `feedback`.

Until step 2 to 4 are done the form answers "Feedback is not set up yet" and nothing is stored.

## How the pieces fit

| Piece | Job |
|---|---|
| `api/feedback.js` | Validates a submission (kind, 1 to 2000 characters, optional email), drops honeypot hits, refuses cross-site posts, and writes one row to Supabase's REST API. The browser never sees a Supabase key. |
| `supabase/migrations/…create_feedback.sql` | The `feedback` table. RLS is on with no policies, so only the service role can read or write it. |
| `vercel.json` | Security headers and caching. |
| `tests/feedback.test.js` | 12 tests with a fake `fetch`. |

## Privacy

The site runs no analytics and sets no cookies. Feedback is stored only if the visitor sends it, and the email is optional.
Vercel and Supabase keep their own ordinary operational logs. Say so in any privacy notice you publish.

## Licences

GSAP (`assets/vendor`) is used under its "Standard no charge" licence. Shippori Mincho, IBM Plex Sans and IBM Plex Mono
are under the SIL Open Font Licence 1.1. The screenshots show only the synthetic `samples/nexus-demo.pcap`.

# VERUS — Next.js frontend

## 1. Environment

Create `.env.local` in the project root:

```env
NEXT_PUBLIC_SUPABASE_URL=https://mqvigqnlzqqmhuttmith.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=YOUR_SUPABASE_PUBLISHABLE_KEY
```

Use the Supabase **Publishable** key. Never use the `sb_secret_...` key in browser code.

## 2. Install

```bash
npm install
```

## 3. Run

```bash
npm run dev
```

Open http://localhost:3000

## 4. Supabase

The page expects these public database objects:

- `documents`
- `verification_events`
- `ledger_anchors`
- `ledger_feed`

Run the previously supplied `supabase_setup_SIH26188.sql` in Supabase SQL Editor if they are not already configured.

## 5. Vercel

Add the same two `NEXT_PUBLIC_...` variables in Vercel Project Settings -> Environment Variables for Production/Preview/Development, then redeploy.

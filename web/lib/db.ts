import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './auth-schema';

const url = process.env.DATABASE_URL_WEB ?? 'postgres://depguard_web:depguard_web@localhost:5432/depguard_web';

// Application data (orgs, invitations, memberships, auth tables) lives in local
// PostgreSQL. Supabase is only used for Auth — reject a Supabase DSN here so a
// misconfigured deployment fails loudly instead of silently writing app data to Supabase.
if (/pooler\.supabase\.com|\.supabase\.co/i.test(url)) {
  throw new Error(
    'DATABASE_URL_WEB must point at local PostgreSQL. Supabase is only for Auth ' +
      '(NEXT_PUBLIC_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_ANON_KEY / SUPABASE_SERVICE_ROLE_KEY).',
  );
}

export const db = drizzle(postgres(url, { max: 10 }), { schema });
export { schema };

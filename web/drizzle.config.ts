import type { Config } from 'drizzle-kit';

export default {
  schema: './lib/auth-schema.ts',
  out: './drizzle',
  dialect: 'postgresql',
  dbCredentials: { url: process.env.DATABASE_URL_WEB! },
} satisfies Config;

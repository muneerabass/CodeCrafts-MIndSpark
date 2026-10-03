import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './auth-schema';

const url = process.env.DATABASE_URL_WEB ?? 'postgres://depguard_web:depguard_web@localhost:5432/depguard_web';
export const db = drizzle(postgres(url, { max: 10, ssl: url.includes('supabase') ? 'require' : false }), { schema });
export { schema };

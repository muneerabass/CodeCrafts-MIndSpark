import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './auth-schema';

// Better Auth tables only. The Go API owns every domain table (separate role/database).
const url = process.env.DATABASE_URL_WEB ?? 'postgres://depguard_web:depguard_web@localhost:5432/depguard_web';
export const db = drizzle(postgres(url, { max: 10 }), { schema });
export { schema };

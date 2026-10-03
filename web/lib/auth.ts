import 'server-only';

export const publicUrl = process.env.PUBLIC_URL ?? 'http://localhost:3000';

export const superadminEmails = (process.env.SUPERADMIN_EMAILS ?? '')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

export const enabledProviders: ('github' | 'google')[] = [
  ...(process.env.NEXT_PUBLIC_SUPABASE_GITHUB_ENABLED !== '0' ? (['github'] as const) : []),
  ...(process.env.NEXT_PUBLIC_SUPABASE_GOOGLE_ENABLED === '1' ? (['google'] as const) : []),
];

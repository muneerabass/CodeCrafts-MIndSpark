import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get('code');
  const next = searchParams.get('next') ?? '/dashboard';

  if (code) {
    const supabase = await createClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) {
      const safeNext = next && /^\/(?![/\\])/.test(next) ? next : '/dashboard';
      return NextResponse.redirect(`${origin}${safeNext}`);
    }
    console.error('[auth/callback] exchangeCodeForSession error:', error.message, error);
  }

  const errorCode = searchParams.get('error') ?? 'unknown';
  const errorDesc = searchParams.get('error_description') ?? '';
  console.error('[auth/callback] OAuth error:', { code, errorCode, errorDesc });
  return NextResponse.redirect(`${origin}/sign-in?error=auth_callback_error`);
}

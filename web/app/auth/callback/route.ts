import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { publicUrl } from '@/lib/auth';

export async function GET(request: Request) {
  // Behind the reverse proxy request.url is the internal address, so redirect to the public URL.
  const { searchParams } = new URL(request.url);
  const origin = publicUrl;
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

import { NextResponse, type NextRequest } from 'next/server';
import { createServerClient } from '@supabase/ssr';

const PUBLIC = ['/sign-in', '/accept-invitation', '/attributions', '/auth/callback', '/badges'];
const bypass = process.env.NODE_ENV !== 'production' && process.env.E2E_AUTH_BYPASS === '1';

export async function proxy(req: NextRequest) {
  const { pathname, search } = req.nextUrl;
  if (bypass || pathname === '/' || PUBLIC.some((p) => pathname === p || pathname.startsWith(`${p}/`))) return NextResponse.next();

  // Refresh Supabase auth tokens on every request.
  let response = NextResponse.next({ request: req });
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: {
      getAll() {
        return req.cookies.getAll();
      },
      setAll(cookiesToSet) {
        for (const { name, value } of cookiesToSet) req.cookies.set(name, value);
        response = NextResponse.next({ request: req });
        for (const { name, value, options } of cookiesToSet) response.cookies.set(name, value, options);
      },
    },
  });
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    const url = new URL('/sign-in', req.url);
    if (pathname !== '/') url.searchParams.set('next', pathname + search);
    return NextResponse.redirect(url);
  }

  // Super-admin area.
  if (pathname === '/admin' || pathname.startsWith('/admin/')) {
    const { superadminEmails } = await import('@/lib/auth');
    const sa = user.app_metadata?.role === 'admin' || superadminEmails.includes(user.email?.toLowerCase() ?? '');
    if (!sa) return pathname.startsWith('/admin/river') ? new NextResponse('Not found', { status: 404 }) : NextResponse.redirect(new URL('/dashboard', req.url));
  }

  return response;
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|icon.svg|favicon.ico).*)'],
};

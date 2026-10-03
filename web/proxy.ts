import { NextResponse, type NextRequest } from 'next/server';
import { getSessionCookie } from 'better-auth/cookies';

const PUBLIC = ['/sign-in', '/accept-invitation', '/attributions', '/api/auth'];
const bypass = process.env.NODE_ENV !== 'production' && process.env.E2E_AUTH_BYPASS === '1';

export async function proxy(req: NextRequest) {
  const { pathname, search } = req.nextUrl;
  if (bypass || PUBLIC.some((p) => pathname === p || pathname.startsWith(`${p}/`))) return NextResponse.next();

  if (!getSessionCookie(req)) {
    const url = new URL('/sign-in', req.url);
    if (pathname !== '/') url.searchParams.set('next', pathname + search);
    return NextResponse.redirect(url);
  }

  // Super-admin area: verify the session for real (cookie presence is not enough).
  if (pathname === '/admin' || pathname.startsWith('/admin/')) {
    const { auth, superadminEmails } = await import('@/lib/auth');
    const s = await auth.api.getSession({ headers: req.headers });
    const sa = s && (s.user.role === 'admin' || superadminEmails.includes(s.user.email.toLowerCase()));
    if (!sa) return pathname.startsWith('/admin/river') ? new NextResponse('Not found', { status: 404 }) : NextResponse.redirect(new URL('/dashboard', req.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|icon.svg|favicon.ico).*)'],
};

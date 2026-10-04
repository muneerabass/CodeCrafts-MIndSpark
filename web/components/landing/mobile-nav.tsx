'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Menu, X } from 'lucide-react';

/** Hamburger menu for the landing header below the `lg` breakpoint. */
export function MobileNav({ links, signIn, signUp }: { links: [string, string][]; signIn: string; signUp: string }) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('keydown', onKey);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
    };
  }, [open]);

  return (
    <div className="lg:hidden">
      <button
        type="button"
        aria-label="Open menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="grid size-9 place-items-center text-white"
      >
        <Menu className="size-5" />
      </button>
      {open && (
        <div role="dialog" aria-modal="true" aria-label="Menu" className="fixed inset-0 z-50 overflow-y-auto bg-black px-5 pb-8">
          <div className="flex h-16 items-center justify-end">
            <button type="button" aria-label="Close menu" onClick={() => setOpen(false)} className="grid size-9 place-items-center text-white">
              <X className="size-5" />
            </button>
          </div>
          <nav className="flex flex-col">
            {links.map(([label, href]) => (
              <a key={label} href={href} onClick={() => setOpen(false)} className="border-b border-white/10 py-4 text-lg !text-[rgb(229_236_246)] hover:!text-white">
                {label}
              </a>
            ))}
          </nav>
          <div className="mt-8 flex flex-col gap-3">
            <Link href={signUp} className="rounded-lg bg-[#7c3aed] py-3 text-center text-[16px] font-medium !text-white">Get started</Link>
            <Link href={signIn} className="rounded-lg border border-white/20 py-3 text-center text-[16px] !text-white">Sign in</Link>
          </div>
        </div>
      )}
    </div>
  );
}

'use client';

import { useSyncExternalStore } from 'react';
import { Palette } from 'lucide-react';
import { SidebarMenuButton } from '@/components/ui/sidebar';
import { DEFAULT_THEME, THEMES, THEME_COOKIE, type ThemeId } from '@/lib/theme';

// The theme lives on <html data-theme>; read it as an external store so the label follows changes.
function subscribe(cb: () => void) {
  const mo = new MutationObserver(cb);
  mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  return () => mo.disconnect();
}
const current = () => (document.documentElement.dataset.theme as ThemeId) || DEFAULT_THEME;

/** Cycles through themes; persists in a cookie so the server renders the right one (no flash). */
export function ThemeSwitcher({ compact = false }: { compact?: boolean }) {
  const theme = useSyncExternalStore(subscribe, current, () => DEFAULT_THEME);
  const cur = THEMES.find((t) => t.id === theme) ?? THEMES[0];
  const next = () => {
    const n = THEMES[(THEMES.findIndex((t) => t.id === theme) + 1) % THEMES.length];
    document.cookie = `${THEME_COOKIE}=${n.id}; path=/; max-age=31536000; samesite=lax`;
    const el = document.documentElement;
    el.dataset.theme = n.id;
    el.classList.toggle('dark', n.dark);
  };
  if (compact)
    return (
      <button
        type="button"
        onClick={next}
        aria-label={`Switch theme (now ${cur.label})`}
        title={`Theme: ${cur.label}`}
        className="flex flex-1 justify-center rounded-md p-2 text-muted-foreground transition-colors hover:bg-sidebar-accent hover:text-foreground"
      >
        <Palette className="size-4" />
      </button>
    );
  return (
    <SidebarMenuButton onClick={next} tooltip="Switch theme" className="text-muted-foreground">
      <Palette /> <span>Theme: {cur.label}</span>
    </SidebarMenuButton>
  );
}

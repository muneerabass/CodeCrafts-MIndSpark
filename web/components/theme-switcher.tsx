'use client';

import { useEffect, useState } from 'react';
import { Palette } from 'lucide-react';
import { SidebarMenuButton } from '@/components/ui/sidebar';
import { DEFAULT_THEME, THEMES, THEME_COOKIE, type ThemeId } from '@/lib/theme';

/** Cycles through themes; persists in a cookie so the server renders the right one (no flash). */
export function ThemeSwitcher() {
  const [theme, setTheme] = useState<ThemeId>(DEFAULT_THEME);
  useEffect(() => setTheme(document.documentElement.dataset.theme as ThemeId), []);
  const cur = THEMES.find((t) => t.id === theme)!;
  const next = () => {
    const n = THEMES[(THEMES.findIndex((t) => t.id === theme) + 1) % THEMES.length];
    document.cookie = `${THEME_COOKIE}=${n.id}; path=/; max-age=31536000; samesite=lax`;
    const el = document.documentElement;
    el.dataset.theme = n.id;
    el.classList.toggle('dark', n.dark);
    setTheme(n.id);
  };
  return (
    <SidebarMenuButton onClick={next} tooltip="Switch theme" className="text-muted-foreground">
      <Palette /> <span>Theme: {cur.label}</span>
    </SidebarMenuButton>
  );
}

export const THEMES = [
  { id: 'cyber', label: 'Violet (dark)', dark: true },
  { id: 'classic', label: 'Violet (light)', dark: false },
] as const;

export type ThemeId = (typeof THEMES)[number]['id'];

/** Set to 'classic' to restore the original look for everyone without a saved preference. */
export const DEFAULT_THEME: ThemeId = 'cyber';
export const THEME_COOKIE = 'dg-theme';

export function resolveTheme(v: string | undefined): (typeof THEMES)[number] {
  return THEMES.find((t) => t.id === v) ?? THEMES.find((t) => t.id === DEFAULT_THEME)!;
}

import { Chivo_Mono, Inter_Tight, Mona_Sans } from 'next/font/google';

// Marketing surfaces (landing + sign-in) share one type system, scoped under `.lp`.
const display = Mona_Sans({ subsets: ['latin'], weight: ['400', '500'], variable: '--lp-display' });
const sans = Inter_Tight({ subsets: ['latin'], weight: ['400', '500'], variable: '--lp-sans' });
const mono = Chivo_Mono({ subsets: ['latin'], weight: ['400'], variable: '--lp-mono' });

export const landingFonts = `${display.variable} ${sans.variable} ${mono.variable}`;

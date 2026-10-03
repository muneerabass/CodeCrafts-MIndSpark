import './globals.css';
import './themes.css';
import { cookies } from 'next/headers';
import { IBM_Plex_Sans, JetBrains_Mono, Space_Grotesk } from 'next/font/google';
import { THEME_COOKIE, resolveTheme } from '@/lib/theme';

const sans = IBM_Plex_Sans({ subsets: ['latin'], weight: ['400', '500', '600'], variable: '--font-body' });
const display = Space_Grotesk({ subsets: ['latin'], variable: '--font-heading' });
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-code' });
import type { Metadata } from 'next';
import { NuqsAdapter } from 'nuqs/adapters/next/app';
import { TooltipProvider } from '@/components/ui/tooltip';
import { Toaster } from '@/components/ui/sonner';

export const metadata: Metadata = {
  title: { default: 'depguard', template: '%s · depguard' },
  description: 'Software supply-chain security for your repositories, pipelines and developer machines.',
  icons: { icon: '/icon.svg' },
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const theme = resolveTheme((await cookies()).get(THEME_COOKIE)?.value);
  return (
    <html
      lang="en"
      data-theme={theme.id}
      suppressHydrationWarning
      className={`${sans.variable} ${display.variable} ${mono.variable} ${theme.dark ? 'dark' : ''}`}
    >
      <body className="min-h-dvh font-sans">
        <NuqsAdapter>
          <TooltipProvider delayDuration={200}>{children}</TooltipProvider>
        </NuqsAdapter>
        <Toaster richColors position="top-right" />
      </body>
    </html>
  );
}

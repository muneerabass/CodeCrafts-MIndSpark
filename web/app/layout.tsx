import './globals.css';
import type { Metadata } from 'next';
import { NuqsAdapter } from 'nuqs/adapters/next/app';
import { TooltipProvider } from '@/components/ui/tooltip';
import { Toaster } from '@/components/ui/sonner';

export const metadata: Metadata = {
  title: { default: 'depguard', template: '%s · depguard' },
  description: 'Software supply-chain security for your repositories, pipelines and developer machines.',
  icons: { icon: '/icon.svg' },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-dvh font-sans">
        <NuqsAdapter>
          <TooltipProvider delayDuration={200}>{children}</TooltipProvider>
        </NuqsAdapter>
        <Toaster richColors position="top-right" />
      </body>
    </html>
  );
}

'use client';

import { useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';
import { Check, Copy, Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import type { ActionResult } from '@/lib/actions';

export function CopyButton({ value, label, className, variant = 'ghost' }: { value: string; label?: string; className?: string; variant?: 'ghost' | 'outline' }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      type="button"
      variant={variant}
      size={label ? 'default' : 'icon'}
      className={className}
      aria-label={label ? undefined : 'Copy to clipboard'}
      onClick={async () => {
        await navigator.clipboard.writeText(value);
        setDone(true);
        toast.success('Copied to clipboard');
        setTimeout(() => setDone(false), 1500);
      }}
    >
      {done ? <Check /> : <Copy />}
      {label}
    </Button>
  );
}

/** Runs a server action, toasts the outcome and refreshes server components. */
export function useAction() {
  const router = useRouter();
  const [pending, start] = useTransition();
  const run = <T,>(fn: () => Promise<ActionResult<T>>, ok?: string) =>
    new Promise<T | undefined>((resolve) =>
      start(async () => {
        const r = await fn();
        if (!r.ok) {
          toast.error(r.error);
          return resolve(undefined);
        }
        if (ok) toast.success(ok);
        router.refresh();
        resolve(r.data);
      }),
    );
  return { pending, run };
}

/** A button that runs one server action. */
export function ActionButton({
  action,
  ok,
  children,
  confirm,
  ...props
}: { action: () => Promise<ActionResult<unknown>>; ok?: string; confirm?: string } & Omit<React.ComponentProps<typeof Button>, 'onClick' | 'action'>) {
  const { pending, run } = useAction();
  return (
    <Button
      {...props}
      disabled={pending || props.disabled}
      onClick={() => {
        if (confirm && !window.confirm(confirm)) return;
        run(action, ok);
      }}
    >
      {pending && <Loader2 className="animate-spin" />}
      {children}
    </Button>
  );
}

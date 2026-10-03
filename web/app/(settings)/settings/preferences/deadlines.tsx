'use client';

import { useState } from 'react';
import { Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAction } from '@/components/client';
import { saveSLA } from '@/lib/actions';
import type { SLA } from '@/lib/types';

const LEVELS: { key: keyof SLA; label: string }[] = [
  { key: 'critical', label: 'Critical' },
  { key: 'high', label: 'High' },
  { key: 'medium', label: 'Medium' },
  { key: 'low', label: 'Low' },
];

/** Days to fix a vulnerability by risk level; 0 turns the deadline off. */
export function DeadlinesForm({ initial, canEdit }: { initial: SLA; canEdit: boolean }) {
  const [s, setS] = useState(initial);
  const [saved, setSaved] = useState(JSON.stringify(initial));
  const { pending, run } = useAction();
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {LEVELS.map((l) => (
          <div key={l.key}>
            <Label htmlFor={`sla-${l.key}`}>{l.label}</Label>
            <div className="mt-1.5 flex items-center gap-2">
              <Input
                id={`sla-${l.key}`}
                type="number"
                min={0}
                max={365}
                value={s[l.key]}
                disabled={!canEdit}
                onChange={(e) => setS({ ...s, [l.key]: Math.max(0, Math.min(365, Number(e.target.value) || 0)) })}
                className="w-20"
              />
              <span className="text-sm text-muted-foreground">days</span>
            </div>
          </div>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">The clock starts when depguard first finds the vulnerability in your projects. 0 means no deadline.</p>
      {canEdit && (
        <div className="flex justify-end">
          <Button
            disabled={JSON.stringify(s) === saved || pending}
            onClick={() =>
              run(() => saveSLA(s), 'Fix deadlines saved').then((r) => {
                if (r) {
                  setS(r);
                  setSaved(JSON.stringify(r));
                }
              })
            }
          >
            {pending && <Loader2 className="size-4 animate-spin" />} Save deadlines
          </Button>
        </div>
      )}
    </div>
  );
}

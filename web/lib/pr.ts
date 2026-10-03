import type { UrgencyLevel } from './types';

export const LEVELS: UrgencyLevel[] = ['critical', 'high', 'medium', 'low', 'clean', 'pending'];

export const levelLabel: Record<UrgencyLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  clean: 'Clean',
  pending: 'Pending',
};

export const PR_STATE_OPTIONS = [
  { value: 'open', label: 'Open' },
  { value: 'merged', label: 'Merged' },
  { value: 'closed', label: 'Closed' },
  { value: 'all', label: 'All' },
];

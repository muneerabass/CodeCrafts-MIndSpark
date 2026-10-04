const csvCell = (v: unknown) => {
  const s = v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
  return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
};

/** Downloads rows as a CSV file (browser only). */
export function downloadCsv(name: string, columns: string[], rows: unknown[][]) {
  const lines = [columns.map(csvCell).join(','), ...rows.map((r) => r.map(csvCell).join(','))];
  const url = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/csv' }));
  const a = Object.assign(document.createElement('a'), { href: url, download: `${name}-${new Date().toISOString().slice(0, 19)}.csv` });
  a.click();
  URL.revokeObjectURL(url);
}

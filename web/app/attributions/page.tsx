import Link from 'next/link';
import { ExternalLink } from 'lucide-react';
import { Logo } from '@/components/icons';

export const metadata = { title: 'Attributions' };

const sources = [
  { name: 'OSV (Open Source Vulnerabilities)', url: 'https://osv.dev', license: 'CC-BY 4.0', use: 'Vulnerability and malicious-package advisories, mirrored locally.' },
  { name: 'deps.dev (Open Source Insights)', url: 'https://deps.dev', license: 'CC-BY 4.0', use: 'Package licenses and source-repository metadata.' },
  { name: 'FIRST EPSS', url: 'https://www.first.org/epss', license: 'Free to use per FIRST EPSS usage terms (attribution requested)', use: 'Exploit Prediction Scoring System probabilities for CVEs.' },
  { name: 'CISA Known Exploited Vulnerabilities', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', license: 'Public domain (CC0 1.0)', use: 'Flags vulnerabilities known to be exploited in the wild.' },
  { name: 'OpenSSF Scorecard', url: 'https://github.com/ossf/scorecard', license: 'Apache-2.0', use: 'Project maintenance and security-practice scores.' },
  { name: 'OpenSSF malicious-packages', url: 'https://github.com/ossf/malicious-packages', license: 'Apache-2.0', use: 'Known malicious packages (MAL- advisories, delivered via OSV).' },
  { name: 'safedep/vet', url: 'https://github.com/safedep/vet', license: 'Apache-2.0', use: 'Lockfile parsing, scanning pipeline and CEL policy evaluation (used as a library).' },
  { name: 'DataDog/guarddog', url: 'https://github.com/DataDog/guarddog', license: 'Apache-2.0', use: 'Heuristic malware analysis of packages, and the top-package lists and lookalike-name (typosquat) heuristics.' },
  { name: 'npm-rank', url: 'https://github.com/tristan-f-r/npm-rank', license: 'MIT', use: 'Top npm package list for lookalike-name (typosquat) detection.' },
  { name: 'ecosyste.ms', url: 'https://ecosyste.ms', license: 'CC BY-SA 4.0', use: 'Top RubyGems package list for lookalike-name (typosquat) detection.' },
  { name: 'Top PyPI Packages (hugovk/top-pypi-packages)', url: 'https://hugovk.dev/top-pypi-packages/', license: 'Downloaded at runtime', use: 'Top PyPI package list for lookalike-name (typosquat) detection.' },
  {
    name: 'OSADL Open Source License Checklists',
    url: 'https://www.osadl.org/checklists',
    license: 'CC BY 4.0',
    use: 'License compatibility data: OSADL Open Source License Checklists — A project by the Open Source Automation Development Lab (OSADL) eG. For further information about the project see the description at www.osadl.org/checklists. Licensed under CC BY 4.0.',
  },
];

export default function AttributionsPage() {
  return (
    <main className="mx-auto max-w-3xl px-4 py-10">
      <Link href="/" className="mb-8 flex items-center gap-2 font-semibold">
        <Logo /> depguard
      </Link>
      <h1 className="text-2xl font-semibold">Data sources &amp; attributions</h1>
      <p className="mt-2 text-sm text-muted-foreground">
        depguard builds on open data and open-source software. We thank the projects below and credit them as their licenses require.
      </p>
      <ul className="mt-6 divide-y rounded-xl border bg-card">
        {sources.map((s) => (
          <li key={s.name} className="p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <a href={s.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-medium hover:text-primary hover:underline">
                {s.name} <ExternalLink className="size-3.5" aria-hidden />
              </a>
              <span className="rounded-md bg-muted px-1.5 py-0.5 text-xs">{s.license}</span>
            </div>
            <p className="mt-1 text-sm text-muted-foreground">{s.use}</p>
          </li>
        ))}
      </ul>
      <p className="mt-6 text-xs text-muted-foreground">
        depguard is an independent project and is not affiliated with, sponsored or endorsed by any of the projects or organizations listed above.
        Data may be modified (normalized, deduplicated, enriched) from its original form.
      </p>
    </main>
  );
}

'use client';

import Link from 'next/link';
import { ChevronDown, Download, FileCheck2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';

/** SBOM downloads and the printable compliance report of one project version. */
export function ExportMenu({ projectId, versionId }: { projectId: string; versionId: string }) {
  const sbom = (f: string) => `/api/projects/${encodeURIComponent(projectId)}/sbom?${new URLSearchParams({ format: f, version: versionId })}`;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm">
          <Download /> <span className="hidden sm:inline">Export</span> <ChevronDown />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel className="text-xs text-muted-foreground">SBOM (software bill of materials)</DropdownMenuLabel>
        <DropdownMenuItem asChild>
          <a href={sbom('cyclonedx')} download>
            CycloneDX 1.6 (.json)
          </a>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <a href={sbom('spdx')} download>
            SPDX 2.3 (.json)
          </a>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link href={`/projects/${encodeURIComponent(projectId)}/report?version=${encodeURIComponent(versionId)}`}>
            <FileCheck2 /> Compliance report (PDF)
          </Link>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

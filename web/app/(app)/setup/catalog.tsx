import { Bot, Server, ShieldCheck, Terminal } from 'lucide-react';
import { BitbucketIcon, GitHubIcon, GitLabIcon } from '@/components/icons';

export type GuideMeta = { title: string; desc: string; Icon: React.ComponentType<{ className?: string }> };

/** Integration catalog shared by /setup/integrations and /setup/guides/[slug]. */
export const guides: Record<string, GuideMeta> = {
  'github-app': { title: 'GitHub App', desc: 'Install the depguard GitHub App and every pull request gets a check run and a single summary comment. Findings flow into Projects on their own.', Icon: GitHubIcon },
  'github-actions': { title: 'GitHub Actions', desc: 'Add a depguard step to your workflow and fail the job when a dependency breaks your policy.', Icon: GitHubIcon },
  'gitlab-ci': { title: 'GitLab CI', desc: 'Run a depguard job in your GitLab pipeline and stop merges that pull in risky packages.', Icon: GitLabIcon },
  'bitbucket-pipes': { title: 'Bitbucket Pipes', desc: 'Scan lockfiles in Bitbucket Pipelines and report results to depguard.', Icon: BitbucketIcon },
  cli: { title: 'CLI', desc: 'Scan any project from your terminal and upload the results to your tenant.', Icon: Terminal },
  pmg: { title: 'PMG', desc: 'Stop malicious packages at install time on laptops and CI runners with Package Manager Guard.', Icon: ShieldCheck },
  mcp: { title: 'MCP Server', desc: 'Give AI coding agents a tool to check packages for malware and vulnerabilities before they install them.', Icon: Server },
  'ai-tools': { title: 'AI Tools Discovery', desc: 'Find the coding agents, MCP servers, agent skills and IDE extensions in use on your machines and track them under Endpoints.', Icon: Bot },
};

export function IconTile({ Icon }: { Icon: GuideMeta['Icon'] }) {
  return (
    <span className="flex size-11 shrink-0 items-center justify-center rounded-lg border bg-muted/60 text-foreground">
      <Icon className="size-5" />
    </span>
  );
}

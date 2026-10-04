import { Bot, PackageCheck, Server, ShieldCheck, Terminal } from 'lucide-react';
import { BitbucketIcon, ContainerIcon, GitHubIcon, GitLabIcon } from '@/components/icons';

export type GuideMeta = { title: string; desc: string; Icon: React.ComponentType<{ className?: string }> };

/** Integration catalog shared by /setup/integrations and /setup/guides/[slug]. */
export const guides: Record<string, GuideMeta> = {
  'github-app': { title: 'GitHub App', desc: 'Install the depguard GitHub App and every pull request gets a check run and a single summary comment. Findings flow into Projects on their own.', Icon: GitHubIcon },
  'github-actions': { title: 'GitHub Actions', desc: 'Add a depguard step to your workflow and fail the job when a dependency breaks your policy.', Icon: GitHubIcon },
  'gitlab-ci': { title: 'GitLab CI', desc: 'Run a depguard job in your GitLab pipeline and stop merges that pull in risky packages.', Icon: GitLabIcon },
  'bitbucket-pipes': { title: 'Bitbucket Pipes', desc: 'Scan lockfiles in Bitbucket Pipelines and report results to depguard.', Icon: BitbucketIcon },
  'install-guard': { title: 'Install Guard', desc: 'Check every npm, pnpm, yarn, pip, uv, poetry, go and cargo install against your policy before anything is installed: vulnerabilities, malware, banned packages and allowed versions.', Icon: PackageCheck },
  container: { title: 'Container images', desc: 'Scan the packages inside a Docker or OCI image, or upload an SBOM from any tool, and track the image as a project.', Icon: ContainerIcon },
  cli: { title: 'CLI', desc: 'Scan any project from your terminal and upload the results to your tenant.', Icon: Terminal },
  pmg: { title: 'PMG', desc: 'Stop malicious packages at install time on laptops and CI runners with Package Manager Guard.', Icon: ShieldCheck },
  mcp: { title: 'AI agents: MCP server + skill', desc: 'One command connects Claude Code, Cursor, VS Code, Windsurf, Gemini CLI and Codex: agents check every package with depguard before installing it.', Icon: Server },
  'ai-tools': { title: 'AI Tools Discovery', desc: 'Find the coding agents, MCP servers, agent skills and IDE extensions in use on your machines and track them under Endpoints.', Icon: Bot },
};

export function IconTile({ Icon }: { Icon: GuideMeta['Icon'] }) {
  return (
    <span className="flex size-11 shrink-0 items-center justify-center rounded-lg border bg-muted/60 text-foreground">
      <Icon className="size-5" />
    </span>
  );
}

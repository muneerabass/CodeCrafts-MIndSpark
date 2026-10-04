import ReactMarkdown, { type Components } from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeRaw from 'rehype-raw';
import rehypeSanitize from 'rehype-sanitize';

// Hosts an AI answer may link to. Anything else renders as plain text so an
// answer can never carry data out through a URL; images are dropped too.
const linkHosts = new Set(['osv.dev', 'github.com', 'nvd.nist.gov']);

export function safeHref(href: string | undefined): string | null {
  if (!href) return null;
  if (href.startsWith('/') && !href.startsWith('//') && !href.startsWith('/\\')) return href;
  try {
    const u = new URL(href);
    if (u.protocol === 'https:' && linkHosts.has(u.hostname)) return u.href;
  } catch {}
  return null;
}

const strictComponents: Components = {
  img: () => null,
  a: ({ href, children }) => {
    const ok = safeHref(href);
    if (!ok) return <span>{children}</span>;
    return ok.startsWith('/') ? (
      <a href={ok}>{children}</a>
    ) : (
      <a href={ok} target="_blank" rel="noreferrer">
        {children}
      </a>
    );
  },
};

/**
 * Renders scan reports (GitHub-flavoured, with <details>), sanitized with GitHub's allow-list.
 * strict (AI answers): no raw HTML, no images, links only inside depguard and to a few trusted hosts.
 */
export function Markdown({ children, strict = false }: { children: string; strict?: boolean }) {
  return (
    <div className="prose-dg">
      {strict ? (
        <ReactMarkdown remarkPlugins={[remarkGfm]} skipHtml components={strictComponents}>
          {children}
        </ReactMarkdown>
      ) : (
        <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeRaw, rehypeSanitize]}>
          {children}
        </ReactMarkdown>
      )}
    </div>
  );
}

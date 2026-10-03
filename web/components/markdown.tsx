import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeRaw from 'rehype-raw';
import rehypeSanitize from 'rehype-sanitize';

/** Renders scan reports (GitHub-flavoured, with <details>), sanitized with GitHub's allow-list. */
export function Markdown({ children }: { children: string }) {
  return (
    <div className="prose-dg">
      <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeRaw, rehypeSanitize]}>
        {children}
      </ReactMarkdown>
    </div>
  );
}

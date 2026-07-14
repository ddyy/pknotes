import { useMemo } from 'react';
import MarkdownIt from 'markdown-it';
import DOMPurify from 'dompurify';

const md = new MarkdownIt({ linkify: true, breaks: false });

// Note content is the user's own, but it's still untrusted at render time
// (pasted content could carry markup). Sanitizing keeps an XSS from ever
// running inside the decrypted vault.
export function Preview({ text }: { text: string }) {
  const html = useMemo(() => DOMPurify.sanitize(md.render(text)), [text]);
  return <div className="preview" dangerouslySetInnerHTML={{ __html: html }} />;
}

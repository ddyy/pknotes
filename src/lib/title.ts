// First prose line wins; fenced code, YAML frontmatter, horizontal rules, and
// image-only lines don't make useful titles.
export function noteTitle(text: string): string {
  let inFence = false;
  let inFrontmatter = false;
  let firstContentLine = true;
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    const isFirst = firstContentLine;
    firstContentLine = false;
    if (/^(```|~~~)/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    if (/^(-{3,}|\*{3,}|_{3,})$/.test(line)) {
      // `---` as the very first content line opens frontmatter; any later
      // delimiter closes it (or is just a horizontal rule).
      inFrontmatter = isFirst;
      continue;
    }
    if (inFrontmatter) continue;
    if (/^!\[[^\]]*\]\([^)]*\)$/.test(line)) continue;
    const title = line.replace(/^#+\s*/, '').trim().slice(0, 60);
    if (title) return title;
  }
  return 'Untitled';
}

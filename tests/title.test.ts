import { test } from 'node:test';
import assert from 'node:assert/strict';
import { noteTitle } from '../src/lib/title.ts';

const cases: [string, string, string][] = [
  ['plain first line', 'Plain first line', 'Plain first line'],
  ['heading is stripped', '# Meeting notes\nbody', 'Meeting notes'],
  ['frontmatter skipped', '---\ntitle: yaml stuff\n---\n# Real Heading\nbody', 'Real Heading'],
  ['code fence skipped', '```js\nconst x = 1;\n```\nActual first prose', 'Actual first prose'],
  ['image-only line skipped', '![screenshot](img.png)\n\nNotes about it', 'Notes about it'],
  ['empty note', '', 'Untitled'],
  ['whitespace only', '   \n\n  ', 'Untitled'],
  ['unclosed fence swallows rest', '```\nunclosed fence', 'Untitled'],
  ['hr after prose is not frontmatter', 'Intro\n---\nMore text', 'Intro'],
  ['leading blank lines', '   \n\n## Spaced heading', 'Spaced heading'],
  ['long line truncated to 60', `${'x'.repeat(100)}`, 'x'.repeat(60)],
];

for (const [name, input, expected] of cases) {
  test(`noteTitle: ${name}`, () => {
    assert.equal(noteTitle(input), expected);
  });
}

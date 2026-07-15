import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError, type NoteRecord } from '../lib/api';
import { decryptNote, encryptNote } from '../lib/crypto';
import { useVault } from '../vault';
import { Editor } from './Editor';
import { Preview } from './Preview';

interface LocalNote {
  id: string;
  text: string;
  version: number;
  createdAt: number;
  updatedAt: number;
  undecryptable?: boolean;
}

type SaveState = 'idle' | 'saving' | 'saved' | 'error';

const AUTOSAVE_MS = 800;

// First prose line wins; fenced code, YAML frontmatter, horizontal rules, and
// image-only lines don't make useful titles.
function noteTitle(text: string): string {
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

function formatWhen(ts: number): string {
  const d = new Date(ts * 1000);
  const today = new Date();
  return d.toDateString() === today.toDateString()
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

export function NotesApp() {
  const { username, masterKey, lock, addPasskey } = useVault();
  const [notes, setNotes] = useState<LocalNote[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saveState, setSaveState] = useState<SaveState>('idle');
  const [showPreview, setShowPreview] = useState(false);
  const [banner, setBanner] = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const notesRef = useRef<LocalNote[]>([]);
  notesRef.current = notes;
  const timersRef = useRef(new Map<string, ReturnType<typeof setTimeout>>());

  // Load and decrypt everything once on unlock. Fine at personal scale; the
  // server can't sort or search content it can't read anyway.
  useEffect(() => {
    if (!masterKey) return;
    let cancelled = false;
    void (async () => {
      const { notes: records } = await api.listNotes();
      const decrypted = await Promise.all(
        records.map(async (r: NoteRecord): Promise<LocalNote> => {
          try {
            return {
              id: r.id,
              text: await decryptNote(masterKey, r.ciphertext),
              version: r.version,
              createdAt: r.created_at,
              updatedAt: r.updated_at,
            };
          } catch {
            return {
              id: r.id,
              text: '',
              version: r.version,
              createdAt: r.created_at,
              updatedAt: r.updated_at,
              undecryptable: true,
            };
          }
        }),
      );
      if (cancelled) return;
      setNotes(decrypted);
      setSelectedId(decrypted[0]?.id ?? null);
      setLoading(false);
    })().catch((err) => {
      if (!cancelled) {
        setBanner(err instanceof Error ? err.message : String(err));
        setLoading(false);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [masterKey]);

  useEffect(() => {
    const timers = timersRef.current;
    return () => timers.forEach((t) => clearTimeout(t));
  }, []);

  const saveNote = useCallback(
    async (id: string) => {
      if (!masterKey) return;
      const note = notesRef.current.find((n) => n.id === id);
      if (!note || note.undecryptable) return;
      setSaveState('saving');
      try {
        const ciphertext = await encryptNote(masterKey, note.text);
        const result = await api.updateNote(id, ciphertext, note.version);
        setNotes((prev) =>
          prev.map((n) => (n.id === id ? { ...n, version: result.version, updatedAt: result.updated_at } : n)),
        );
        setSaveState('saved');
      } catch (err) {
        if (err instanceof ApiError && err.status === 409 && err.body.current) {
          // Another device saved first. Keep the server copy as this note and
          // preserve the local text as a separate conflict note.
          const current = err.body.current as NoteRecord;
          const localText = note.text;
          // A server copy that fails to decrypt must surface as undecryptable,
          // not silently become an empty note.
          const serverText = await decryptNote(masterKey, current.ciphertext).catch(() => null);
          setNotes((prev) =>
            prev.map((n) =>
              n.id === id
                ? {
                    ...n,
                    text: serverText ?? '',
                    undecryptable: serverText === null ? true : n.undecryptable,
                    version: current.version,
                    updatedAt: current.updated_at,
                  }
                : n,
            ),
          );
          const conflictText = `> Conflict copy — this device's version of "${noteTitle(localText)}"\n\n${localText}`;
          const created = await api.createNote(await encryptNote(masterKey, conflictText));
          setNotes((prev) => [
            {
              id: created.id,
              text: conflictText,
              version: created.version,
              createdAt: created.created_at,
              updatedAt: created.updated_at,
            },
            ...prev,
          ]);
          setBanner('This note was changed elsewhere. Your local version was kept as a conflict copy.');
          setSaveState('saved');
        } else {
          setSaveState('error');
          setBanner(err instanceof Error ? err.message : String(err));
        }
      }
    },
    [masterKey],
  );

  // Save immediately when the tab is hidden or unloading, so edits sitting in
  // the debounce window aren't lost to a close/switch.
  useEffect(() => {
    const flush = () => {
      const timers = timersRef.current;
      timers.forEach((t, id) => {
        clearTimeout(t);
        void saveNote(id);
      });
      timers.clear();
    };
    const onVisibility = () => {
      if (document.visibilityState === 'hidden') flush();
    };
    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('pagehide', flush);
    return () => {
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('pagehide', flush);
    };
  }, [saveNote]);

  const onEdit = useCallback(
    (id: string, text: string) => {
      setNotes((prev) => prev.map((n) => (n.id === id ? { ...n, text } : n)));
      setSaveState('idle');
      const timers = timersRef.current;
      const existing = timers.get(id);
      if (existing) clearTimeout(existing);
      timers.set(
        id,
        setTimeout(() => {
          timers.delete(id);
          void saveNote(id);
        }, AUTOSAVE_MS),
      );
    },
    [saveNote],
  );

  const createNote = useCallback(async () => {
    if (!masterKey) return;
    const created = await api.createNote(await encryptNote(masterKey, ''));
    setNotes((prev) => [
      { id: created.id, text: '', version: created.version, createdAt: created.created_at, updatedAt: created.updated_at },
      ...prev,
    ]);
    setSelectedId(created.id);
    setShowPreview(false);
    setSidebarOpen(false);
  }, [masterKey]);

  const deleteNote = useCallback(
    async (id: string) => {
      const note = notesRef.current.find((n) => n.id === id);
      if (!note) return;
      if (!window.confirm(`Delete "${noteTitle(note.text)}"? This cannot be undone.`)) return;
      await api.deleteNote(id).catch(() => undefined);
      setNotes((prev) => {
        const next = prev.filter((n) => n.id !== id);
        setSelectedId((sel) => (sel === id ? (next[0]?.id ?? null) : sel));
        return next;
      });
    },
    [],
  );

  const onAddPasskey = useCallback(async () => {
    try {
      await addPasskey();
      setBanner('New passkey added. You can now unlock from that device.');
    } catch (err) {
      setBanner(err instanceof Error ? err.message : String(err));
    }
  }, [addPasskey]);

  const selected = notes.find((n) => n.id === selectedId) ?? null;
  const sorted = [...notes].sort((a, b) => b.updatedAt - a.updatedAt);

  return (
    <div className="app-shell">
      {sidebarOpen && <button type="button" className="scrim" aria-label="Close notes list" onClick={() => setSidebarOpen(false)} />}
      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
        <header className="sidebar-header">
          <span className="brand">pknotes</span>
          <button type="button" className="primary small" onClick={() => void createNote()}>
            + New
          </button>
        </header>
        <ul className="note-list">
          {sorted.map((n) => (
            <li key={n.id}>
              <button
                type="button"
                className={`note-item ${n.id === selectedId ? 'active' : ''}`}
                onClick={() => {
                  setSelectedId(n.id);
                  setSidebarOpen(false);
                }}
              >
                <span className="note-title">{n.undecryptable ? '⚠️ Cannot decrypt' : noteTitle(n.text)}</span>
                <span className="note-when">{formatWhen(n.updatedAt)}</span>
              </button>
            </li>
          ))}
          {!loading && notes.length === 0 && <li className="empty">No notes yet.</li>}
        </ul>
        <footer className="sidebar-footer">
          <span className="user" title={`Signed in as ${username ?? ''}`}>
            {username}
          </span>
          <button type="button" className="ghost small" onClick={() => void onAddPasskey()}>
            Add passkey
          </button>
          <button type="button" className="ghost small" onClick={() => void lock()}>
            Lock
          </button>
        </footer>
      </aside>

      <main className="main-pane">
        {banner && (
          <div className="banner" role="status">
            <span>{banner}</span>
            <button type="button" className="ghost small" onClick={() => setBanner(null)}>
              ✕
            </button>
          </div>
        )}
        {loading ? (
          <div className="placeholder">Decrypting your notes…</div>
        ) : (
          <>
            <div className={`note-toolbar ${selected ? '' : 'no-note'}`}>
              <div className="toolbar-actions">
                <button
                  type="button"
                  className="ghost small menu-button"
                  aria-expanded={sidebarOpen}
                  onClick={() => setSidebarOpen(true)}
                >
                  ☰ Notes
                </button>
                <span className={`save-state ${saveState}`}>
                  {selected &&
                    (saveState === 'saving' ? 'Saving…' : saveState === 'saved' ? 'Saved' : saveState === 'error' ? 'Save failed' : '')}
                </span>
              </div>
              {selected && (
                <div className="toolbar-actions">
                  <button type="button" className="ghost small" onClick={() => setShowPreview((p) => !p)}>
                    {showPreview ? 'Edit' : 'Preview'}
                  </button>
                  <button type="button" className="ghost small danger" onClick={() => void deleteNote(selected.id)}>
                    Delete
                  </button>
                </div>
              )}
            </div>
            {!selected ? (
              <div className="placeholder">Select a note or create a new one.</div>
            ) : selected.undecryptable ? (
              <div className="placeholder">
                This note could not be decrypted with the current key. It may have been written with a different
                master key.
              </div>
            ) : showPreview ? (
              <Preview text={selected.text} />
            ) : (
              <Editor noteId={selected.id} value={selected.text} onChange={(text) => onEdit(selected.id, text)} />
            )}
          </>
        )}
      </main>
    </div>
  );
}

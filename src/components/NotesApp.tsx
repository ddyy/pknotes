import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError, type NoteRecord } from '../lib/api';
import { decryptNote, encryptNote } from '../lib/crypto';
import { noteTitle } from '../lib/title';
import { useVault } from '../vault';
import { Editor } from './Editor';
import { EyeIcon, GearIcon, LockIcon, MenuIcon, PencilIcon, PlusIcon, TrashIcon, WarnIcon } from './icons';
import { Preview } from './Preview';
import { Settings } from './Settings';

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

function formatWhen(ts: number): string {
  const d = new Date(ts * 1000);
  const today = new Date();
  return d.toDateString() === today.toDateString()
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

export function NotesApp() {
  const { username, masterKey, lock } = useVault();
  const [notes, setNotes] = useState<LocalNote[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saveState, setSaveState] = useState<SaveState>('idle');
  const [showPreview, setShowPreview] = useState(false);
  const [banner, setBanner] = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [query, setQuery] = useState('');

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
              text: await decryptNote(masterKey, r.ciphertext, r.id),
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
        const ciphertext = await encryptNote(masterKey, note.text, id);
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
          const serverText = await decryptNote(masterKey, current.ciphertext, id).catch(() => null);
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
          const conflictId = crypto.randomUUID();
          const created = await api.createNote(conflictId, await encryptNote(masterKey, conflictText, conflictId));
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
    const id = crypto.randomUUID();
    const created = await api.createNote(id, await encryptNote(masterKey, '', id));
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

  const selected = notes.find((n) => n.id === selectedId) ?? null;
  const sorted = [...notes].sort((a, b) => b.updatedAt - a.updatedAt);
  // Everything is already decrypted in memory, so search is a plain filter —
  // the server couldn't help anyway.
  const q = query.trim().toLowerCase();
  const visible = q ? sorted.filter((n) => n.text.toLowerCase().includes(q)) : sorted;

  return (
    <div className="app-shell">
      {sidebarOpen && <button type="button" className="scrim" aria-label="Close notes list" onClick={() => setSidebarOpen(false)} />}
      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
        <header className="sidebar-header">
          <span className="brand">pknotes</span>
          <button type="button" className="primary small" onClick={() => void createNote()}>
            <PlusIcon /> New
          </button>
        </header>
        <input
          type="search"
          className="note-search"
          placeholder="Search notes…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <ul className="note-list">
          {visible.map((n) => (
            <li key={n.id}>
              <button
                type="button"
                className={`note-item ${n.id === selectedId ? 'active' : ''}`}
                onClick={() => {
                  setSelectedId(n.id);
                  setSidebarOpen(false);
                }}
              >
                <span className="note-title">
                  {n.undecryptable ? (
                    <>
                      <WarnIcon /> Cannot decrypt
                    </>
                  ) : (
                    noteTitle(n.text)
                  )}
                </span>
                <span className="note-when">{formatWhen(n.updatedAt)}</span>
              </button>
            </li>
          ))}
          {!loading && notes.length === 0 && <li className="empty">No notes yet.</li>}
          {!loading && notes.length > 0 && visible.length === 0 && <li className="empty">No matches.</li>}
        </ul>
        <footer className="sidebar-footer">
          <span className="user" title={`Signed in as ${username ?? ''}`}>
            {username}
          </span>
          <button type="button" className="ghost small" aria-label="Settings" title="Settings" onClick={() => setShowSettings(true)}>
            <GearIcon />
          </button>
          <button type="button" className="ghost small" aria-label="Lock" title="Lock" onClick={() => void lock()}>
            <LockIcon />
          </button>
        </footer>
      </aside>
      {showSettings && (
        <Settings
          notes={notes.map(({ id, text, version, updatedAt, undecryptable }) => ({ id, text, version, updatedAt, undecryptable }))}
          onClose={() => setShowSettings(false)}
          onNotice={setBanner}
        />
      )}

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
          <div className="placeholder pulse">Decrypting your notes…</div>
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
                  <MenuIcon /> Notes
                </button>
                <span className={`save-state ${selected ? saveState : 'idle'}`}>
                  {selected &&
                    (saveState === 'saving' ? 'Saving…' : saveState === 'saved' ? 'Saved' : saveState === 'error' ? 'Save failed' : '')}
                </span>
              </div>
              <div className="toolbar-actions">
                {selected && (
                  <>
                    <button type="button" className="ghost small" onClick={() => setShowPreview((p) => !p)}>
                      {showPreview ? <PencilIcon /> : <EyeIcon />} {showPreview ? 'Edit' : 'Preview'}
                    </button>
                    <button type="button" className="ghost small danger" onClick={() => void deleteNote(selected.id)}>
                      <TrashIcon /> Delete
                    </button>
                  </>
                )}
                <button type="button" className="ghost small lock-button" aria-label="Lock" title="Lock" onClick={() => void lock()}>
                  <LockIcon />
                </button>
              </div>
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

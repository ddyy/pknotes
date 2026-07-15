import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api';
import { noteTitle } from '../lib/title';
import { buildZip } from '../lib/zip';
import { useVault } from '../vault';

interface CredentialInfo {
  id: string;
  transports: string[];
  created_at: number;
}

export interface SettingsNote {
  id: string;
  text: string;
  version: number;
  updatedAt: number;
  undecryptable?: boolean;
}

function exportFilename(note: SettingsNote): string {
  const slug = noteTitle(note.text)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return `${slug || 'untitled'}-${note.id.slice(0, 8)}.md`;
}

export function Settings({
  notes,
  onClose,
  onNotice,
}: {
  notes: SettingsNote[];
  onClose: () => void;
  onNotice: (message: string) => void;
}) {
  const { currentCredentialId, addPasskey, rotate } = useVault();
  const [credentials, setCredentials] = useState<CredentialInfo[] | null>(null);
  const [busy, setBusy] = useState(false);

  const loadCredentials = useCallback(async () => {
    try {
      const result = await api.listCredentials();
      setCredentials(result.credentials);
    } catch (err) {
      onNotice(err instanceof Error ? err.message : String(err));
    }
  }, [onNotice]);

  useEffect(() => {
    void loadCredentials();
  }, [loadCredentials]);

  const removeCredential = useCallback(
    async (id: string) => {
      const warning =
        id === currentCredentialId
          ? 'Remove the passkey you are currently using? You will need another passkey or your recovery code to unlock again.'
          : 'Remove this passkey? The device holding it will no longer be able to unlock your notes.';
      if (!window.confirm(warning)) return;
      try {
        await api.deleteCredential(id);
        await loadCredentials();
      } catch (err) {
        onNotice(err instanceof Error ? err.message : String(err));
      }
    },
    [currentCredentialId, loadCredentials, onNotice],
  );

  const onAddPasskey = useCallback(async () => {
    setBusy(true);
    try {
      await addPasskey();
      await loadCredentials();
      onNotice('New passkey added. You can now unlock from that device.');
    } catch (err) {
      onNotice(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [addPasskey, loadCredentials, onNotice]);

  const onRotate = useCallback(async () => {
    if (
      !window.confirm(
        'Rotate the master key? All notes are re-encrypted with a fresh key. ' +
          'Every passkey EXCEPT the one you confirm with next will stop working and be removed, ' +
          'and your recovery code is replaced with a new one.',
      )
    ) {
      return;
    }
    setBusy(true);
    try {
      await rotate(
        notes.filter((n) => !n.undecryptable).map(({ id, text, version }) => ({ id, text, version })),
      );
      // The vault now shows the new recovery code screen; this panel unmounts.
    } catch (err) {
      onNotice(err instanceof Error ? err.message : String(err));
      setBusy(false);
    }
  }, [notes, onNotice, rotate]);

  const onExport = useCallback(() => {
    const decryptable = notes.filter((n) => !n.undecryptable);
    if (decryptable.length === 0) {
      onNotice('Nothing to export.');
      return;
    }
    const blob = buildZip(
      decryptable.map((n) => ({ name: exportFilename(n), content: n.text, mtime: n.updatedAt })),
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'pknotes-export.zip';
    a.click();
    URL.revokeObjectURL(url);
    const skipped = notes.length - decryptable.length;
    if (skipped > 0) onNotice(`Exported ${decryptable.length} notes; ${skipped} undecryptable note(s) skipped.`);
  }, [notes, onNotice]);

  return (
    <div className="settings-overlay" role="dialog" aria-modal="true" aria-label="Settings">
      <div className="settings-card">
        <header className="settings-header">
          <h2>Settings</h2>
          <button type="button" className="ghost small" onClick={onClose}>
            ✕
          </button>
        </header>

        <section>
          <h3>Passkeys</h3>
          {credentials === null ? (
            <p className="muted">Loading…</p>
          ) : (
            <ul className="credential-list">
              {credentials.map((cred) => (
                <li key={cred.id}>
                  <span className="credential-name">
                    Passkey …{cred.id.slice(-6)}
                    {cred.id === currentCredentialId && <em> (this session)</em>}
                  </span>
                  <span className="credential-when">
                    added {new Date(cred.created_at * 1000).toLocaleDateString()}
                  </span>
                  <button
                    type="button"
                    className="ghost small danger"
                    disabled={credentials.length <= 1}
                    title={credentials.length <= 1 ? 'The last passkey cannot be removed' : undefined}
                    onClick={() => void removeCredential(cred.id)}
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          )}
          <button type="button" className="ghost small" disabled={busy} onClick={() => void onAddPasskey()}>
            Add passkey
          </button>
          <p className="muted">
            Removing a passkey blocks it from signing in, but a compromised device may already hold your data.
            After losing a device, rotate the master key below.
          </p>
        </section>

        <section>
          <h3>Master key</h3>
          <button type="button" className="ghost small danger" disabled={busy} onClick={() => void onRotate()}>
            {busy ? 'Working…' : 'Rotate master key'}
          </button>
          <p className="muted">
            Re-encrypts every note with a fresh key. Only the passkey you confirm with survives; other devices
            must be re-added, and you get a new recovery code.
          </p>
        </section>

        <section>
          <h3>Export</h3>
          <button type="button" className="ghost small" onClick={onExport}>
            Download all notes (.zip)
          </button>
          <p className="muted">Plain markdown files, decrypted locally — keep the archive somewhere safe.</p>
        </section>
      </div>
    </div>
  );
}

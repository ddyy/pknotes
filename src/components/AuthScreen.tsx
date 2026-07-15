import { useState, type FormEvent } from 'react';
import { useVault } from '../vault';
import { KeyIcon } from './icons';

type Mode = 'unlock' | 'create' | 'recover';

export function AuthScreen() {
  const { unlock, register, recover } = useVault();
  const [mode, setMode] = useState<Mode>('unlock');
  const [username, setUsername] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (mode === 'unlock') void run(unlock);
    if (mode === 'create') void run(() => register(username.trim()));
    if (mode === 'recover') void run(() => recover(username.trim(), recoveryCode));
  };

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <h1>pknotes</h1>
        <p className="tagline">End-to-end encrypted notes. Your passkey is the key — literally.</p>

        <div className="mode-tabs" role="tablist">
          {(['unlock', 'create', 'recover'] as const).map((m) => (
            <button
              key={m}
              type="button"
              role="tab"
              aria-selected={mode === m}
              className={mode === m ? 'active' : ''}
              onClick={() => {
                setMode(m);
                setError(null);
              }}
            >
              {m === 'unlock' ? 'Unlock' : m === 'create' ? 'Create account' : 'Recover'}
            </button>
          ))}
        </div>

        <form onSubmit={onSubmit}>
          {mode !== 'unlock' && (
            <label>
              Username
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="username"
                autoComplete="username webauthn"
                required
                minLength={3}
                maxLength={32}
              />
            </label>
          )}
          {mode === 'recover' && (
            <label>
              Recovery code
              <input
                value={recoveryCode}
                onChange={(e) => setRecoveryCode(e.target.value)}
                placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
                required
              />
            </label>
          )}

          {error && <p className="error">{error}</p>}

          <button type="submit" className="primary" disabled={busy}>
            <KeyIcon />
            {busy
              ? 'Waiting for passkey…'
              : mode === 'unlock'
                ? 'Unlock with passkey'
                : mode === 'create'
                  ? 'Create account with passkey'
                  : 'Recover & add new passkey'}
          </button>
        </form>

        {mode === 'unlock' && (
          <p className="hint">Your notes are decrypted locally after Face ID / Touch ID. The server never sees a key.</p>
        )}
        {mode === 'recover' && (
          <p className="hint">Recovery registers a fresh passkey on this device using your one-time recovery code.</p>
        )}
      </div>
    </div>
  );
}

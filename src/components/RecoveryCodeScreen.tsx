import { useVault } from '../vault';

// Shown once — after account creation or a completed recovery (which rotates
// the code) — and gone forever after confirm.
export function RecoveryCodeScreen({ code }: { code: string }) {
  const { confirmRecoveryCode } = useVault();
  return (
    <div className="auth-screen">
      <div className="auth-card">
        <h1>Save your recovery code</h1>
        <p>
          This is the <strong>only</strong> way back into your notes if you lose every passkey. It is shown once
          and never stored anywhere readable. Keep it somewhere safe (password manager, printed copy).
        </p>
        <code className="recovery-code">{code}</code>
        <div className="auth-actions">
          <button type="button" onClick={() => void navigator.clipboard.writeText(code).catch(() => undefined)}>
            Copy
          </button>
          <button type="button" className="primary" onClick={confirmRecoveryCode}>
            I saved it — open my notes
          </button>
        </div>
      </div>
    </div>
  );
}

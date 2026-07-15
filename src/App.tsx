import { useEffect, useState } from 'react';
import { AuthScreen } from './components/AuthScreen';
import { NotesApp } from './components/NotesApp';
import { RecoveryCodeScreen } from './components/RecoveryCodeScreen';
import { api } from './lib/api';
import { useVault, VaultProvider } from './vault';

function Gate() {
  const { status, pendingRecoveryCode } = useVault();
  if (status !== 'unlocked') return <AuthScreen />;
  if (pendingRecoveryCode) return <RecoveryCodeScreen code={pendingRecoveryCode} />;
  return <NotesApp />;
}

export default function App() {
  const [demo, setDemo] = useState(false);
  useEffect(() => {
    api.meta().then((m) => setDemo(m.demo)).catch(() => undefined);
  }, []);
  return (
    <VaultProvider>
      <div className="app-frame">
        {demo && (
          <div className="demo-banner" role="note">
            Demo instance — notes are wiped daily. Don't keep anything real here.
          </div>
        )}
        <div className="app-frame-main">
          <Gate />
        </div>
      </div>
    </VaultProvider>
  );
}

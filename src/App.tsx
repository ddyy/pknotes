import { AuthScreen } from './components/AuthScreen';
import { NotesApp } from './components/NotesApp';
import { RecoveryCodeScreen } from './components/RecoveryCodeScreen';
import { useVault, VaultProvider } from './vault';

function Gate() {
  const { status, pendingRecoveryCode } = useVault();
  if (status !== 'unlocked') return <AuthScreen />;
  if (pendingRecoveryCode) return <RecoveryCodeScreen code={pendingRecoveryCode} />;
  return <NotesApp />;
}

export default function App() {
  return (
    <VaultProvider>
      <Gate />
    </VaultProvider>
  );
}

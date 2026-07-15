import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';
import { api } from './lib/api';
import {
  APP_PRF_SALT,
  b64uEncode,
  generateMasterKeyBytes,
  generateRecoveryCode,
  importMasterKey,
  kekFromPrf,
  recoveryKeysFromCode,
  unwrapMasterKey,
  wrapMasterKey,
} from './lib/crypto';
import { createPasskeyWithPrf, getPasskeyWithPrf, PasskeyError } from './lib/webauthn';

interface VaultValue {
  status: 'locked' | 'unlocked';
  username: string | null;
  /** Master key for note encryption; non-null when unlocked. */
  masterKey: CryptoKey | null;
  /** Set right after registration until the user confirms they saved the code. */
  pendingRecoveryCode: string | null;
  confirmRecoveryCode: () => void;
  register: (username: string) => Promise<void>;
  unlock: () => Promise<void>;
  recover: (username: string, recoveryCode: string) => Promise<void>;
  addPasskey: () => Promise<void>;
  lock: () => Promise<void>;
}

const VaultContext = createContext<VaultValue | null>(null);

export function useVault(): VaultValue {
  const value = useContext(VaultContext);
  if (!value) throw new Error('useVault must be used inside <VaultProvider>');
  return value;
}

const PRF_SALT_B64 = b64uEncode(APP_PRF_SALT);

export function VaultProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<'locked' | 'unlocked'>('locked');
  const [username, setUsername] = useState<string | null>(null);
  const [masterKey, setMasterKey] = useState<CryptoKey | null>(null);
  const [pendingRecoveryCode, setPendingRecoveryCode] = useState<string | null>(null);
  // Raw master key bytes, kept only to wrap under new KEKs when adding a
  // passkey. Never persisted anywhere — a page reload locks the vault.
  const rawMkRef = useRef<Uint8Array | null>(null);

  const becomeUnlocked = useCallback(async (mkRaw: Uint8Array, name: string) => {
    rawMkRef.current = mkRaw;
    setMasterKey(await importMasterKey(mkRaw));
    setUsername(name);
    setStatus('unlocked');
  }, []);

  const register = useCallback(
    async (name: string): Promise<void> => {
      const options = await api.registerOptions(name);
      const { response, prfOutput } = await createPasskeyWithPrf(options);

      const mkRaw = generateMasterKeyBytes();
      const kek = await kekFromPrf(prfOutput);
      await api.registerVerify({
        response,
        prfSalt: PRF_SALT_B64,
        wrappedMk: await wrapMasterKey(kek, mkRaw),
      });

      const recoveryCode = generateRecoveryCode();
      const { kek: recoveryKek, verifier } = await recoveryKeysFromCode(recoveryCode);
      await api.recoverySetup({ verifier, wrappedMk: await wrapMasterKey(recoveryKek, mkRaw) });

      // Set before unlocking so the gate holds on the recovery-code screen.
      setPendingRecoveryCode(recoveryCode);
      await becomeUnlocked(mkRaw, name);
    },
    [becomeUnlocked],
  );

  const confirmRecoveryCode = useCallback(() => setPendingRecoveryCode(null), []);

  const unlock = useCallback(async () => {
    const options = await api.loginOptions();
    const { response, prfOutput } = await getPasskeyWithPrf(options);
    const result = await api.loginVerify({ response });

    const kek = await kekFromPrf(prfOutput);
    let mkRaw: Uint8Array;
    try {
      mkRaw = await unwrapMasterKey(kek, result.wrappedMk);
    } catch {
      throw new PasskeyError('Signed in, but the encryption key could not be unwrapped with this passkey.');
    }
    await becomeUnlocked(mkRaw, result.username);
  }, [becomeUnlocked]);

  const addPasskeyForKey = useCallback(async (mkRaw: Uint8Array) => {
    const options = await api.credentialsOptions();
    const { response, prfOutput } = await createPasskeyWithPrf(options);
    const kek = await kekFromPrf(prfOutput);
    await api.credentialsVerify({
      response,
      prfSalt: PRF_SALT_B64,
      wrappedMk: await wrapMasterKey(kek, mkRaw),
    });
  }, []);

  const recover = useCallback(
    async (name: string, recoveryCode: string) => {
      const { kek, verifier } = await recoveryKeysFromCode(recoveryCode);
      const { wrappedMk } = await api.recoveryRedeem({ username: name, verifier });
      let mkRaw: Uint8Array;
      try {
        mkRaw = await unwrapMasterKey(kek, wrappedMk);
      } catch {
        throw new PasskeyError('That recovery code is not valid for this account.');
      }
      // Re-establish a passkey so the account is usable again going forward.
      await addPasskeyForKey(mkRaw);
      // The redeemed code is spent (single-use on the server) — issue a fresh
      // one and show it before the notes, same as at signup.
      const newCode = generateRecoveryCode();
      const { kek: newKek, verifier: newVerifier } = await recoveryKeysFromCode(newCode);
      await api.recoverySetup({ verifier: newVerifier, wrappedMk: await wrapMasterKey(newKek, mkRaw) });
      setPendingRecoveryCode(newCode);
      await becomeUnlocked(mkRaw, name);
    },
    [addPasskeyForKey, becomeUnlocked],
  );

  const addPasskey = useCallback(async () => {
    if (!rawMkRef.current) throw new PasskeyError('Vault is locked.');
    await addPasskeyForKey(rawMkRef.current);
  }, [addPasskeyForKey]);

  const lock = useCallback(async () => {
    rawMkRef.current = null;
    setMasterKey(null);
    setUsername(null);
    setPendingRecoveryCode(null);
    setStatus('locked');
    await api.logout().catch(() => undefined);
  }, []);

  return (
    <VaultContext.Provider
      value={{
        status,
        username,
        masterKey,
        pendingRecoveryCode,
        confirmRecoveryCode,
        register,
        unlock,
        recover,
        addPasskey,
        lock,
      }}
    >
      {children}
    </VaultContext.Provider>
  );
}

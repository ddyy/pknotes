// Thin wrapper over navigator.credentials that always evaluates the WebAuthn
// PRF extension. Written against the raw API (rather than a helper library)
// so we fully control extension handling and serialization. PRF outputs are
// never sent to the server — they exist only in this tab's memory.

import { APP_PRF_SALT, b64uDecode, b64uEncode } from './crypto';

export class PasskeyError extends Error {}

interface CredentialDescriptorJSON {
  id: string;
  transports?: string[];
}

export interface CreationOptionsJSON {
  challenge: string;
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName?: string };
  pubKeyCredParams: { alg: number; type: 'public-key' }[];
  timeout?: number;
  excludeCredentials?: CredentialDescriptorJSON[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
}

export interface RequestOptionsJSON {
  challenge: string;
  rpId?: string;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
  allowCredentials?: CredentialDescriptorJSON[];
}

export interface RegistrationResponsePayload {
  id: string;
  rawId: string;
  type: string;
  clientExtensionResults: Record<string, never>;
  authenticatorAttachment?: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports: string[];
  };
}

export interface AuthenticationResponsePayload {
  id: string;
  rawId: string;
  type: string;
  clientExtensionResults: Record<string, never>;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
}

const PRF_EXTENSION = { prf: { eval: { first: APP_PRF_SALT } } };

const NO_PRF_SUPPORT_MESSAGE =
  'This passkey provider does not support the PRF extension, which pknotes needs to derive your ' +
  'encryption key (Bitwarden is a known example). No account was created — you can delete the unused ' +
  "passkey from that provider. Try your browser's built-in passkeys instead (Chrome profile, iCloud " +
  "Keychain): dismissing the extension's prompt usually falls back to them.";

interface PrfOutputs {
  enabled?: boolean;
  results?: { first?: ArrayBuffer };
}

function prfExtension(cred: PublicKeyCredential): PrfOutputs {
  return (cred.getClientExtensionResults() as { prf?: PrfOutputs }).prf ?? {};
}

export async function createPasskeyWithPrf(
  options: CreationOptionsJSON,
): Promise<{ response: RegistrationResponsePayload; prfOutput: ArrayBuffer }> {
  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: b64uDecode(options.challenge) as BufferSource,
    rp: options.rp,
    user: {
      id: b64uDecode(options.user.id) as BufferSource,
      name: options.user.name,
      displayName: options.user.displayName ?? options.user.name,
    },
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout,
    excludeCredentials: (options.excludeCredentials ?? []).map((c) => ({
      type: 'public-key' as const,
      id: b64uDecode(c.id) as BufferSource,
      transports: c.transports as AuthenticatorTransport[] | undefined,
    })),
    authenticatorSelection: options.authenticatorSelection,
    attestation: options.attestation,
    extensions: PRF_EXTENSION as AuthenticationExtensionsClientInputs,
  };

  let cred: PublicKeyCredential | null;
  try {
    cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  } catch (err) {
    throw new PasskeyError(describeWebAuthnError(err, 'create'));
  }
  if (!cred) throw new PasskeyError('Passkey creation was cancelled.');

  // Pre-flight before any server call: the provider tells us at creation
  // whether the credential is PRF-capable. Fail with a clear message now
  // rather than a cryptic one later — most authenticators return the PRF
  // output right here; some capable ones only evaluate during get(), so
  // fall back to an immediate assertion for those.
  const prf = prfExtension(cred);
  let prfOutput = prf.results?.first;
  if (!prfOutput) {
    if (!prf.enabled) throw new PasskeyError(NO_PRF_SUPPORT_MESSAGE);
    prfOutput = await evalPrfViaGet(cred.rawId);
  }

  const resp = cred.response as AuthenticatorAttestationResponse;
  return {
    prfOutput,
    response: {
      id: cred.id,
      rawId: b64uEncode(new Uint8Array(cred.rawId)),
      type: cred.type,
      clientExtensionResults: {},
      authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
      response: {
        clientDataJSON: b64uEncode(new Uint8Array(resp.clientDataJSON)),
        attestationObject: b64uEncode(new Uint8Array(resp.attestationObject)),
        transports: resp.getTransports?.() ?? [],
      },
    },
  };
}

export async function getPasskeyWithPrf(
  options: RequestOptionsJSON,
): Promise<{ response: AuthenticationResponsePayload; prfOutput: ArrayBuffer }> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: b64uDecode(options.challenge) as BufferSource,
    rpId: options.rpId,
    timeout: options.timeout,
    userVerification: options.userVerification,
    allowCredentials: (options.allowCredentials ?? []).map((c) => ({
      type: 'public-key' as const,
      id: b64uDecode(c.id) as BufferSource,
      transports: c.transports as AuthenticatorTransport[] | undefined,
    })),
    extensions: PRF_EXTENSION as AuthenticationExtensionsClientInputs,
  };

  let cred: PublicKeyCredential | null;
  try {
    cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  } catch (err) {
    throw new PasskeyError(describeWebAuthnError(err, 'get'));
  }
  if (!cred) throw new PasskeyError('Sign-in was cancelled.');

  const prfOutput = prfExtension(cred).results?.first;
  if (!prfOutput) {
    throw new PasskeyError(
      'This passkey or browser does not support the PRF extension, which pknotes needs for encryption.',
    );
  }

  const resp = cred.response as AuthenticatorAssertionResponse;
  return {
    prfOutput,
    response: {
      id: cred.id,
      rawId: b64uEncode(new Uint8Array(cred.rawId)),
      type: cred.type,
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64uEncode(new Uint8Array(resp.clientDataJSON)),
        authenticatorData: b64uEncode(new Uint8Array(resp.authenticatorData)),
        signature: b64uEncode(new Uint8Array(resp.signature)),
        userHandle: resp.userHandle ? b64uEncode(new Uint8Array(resp.userHandle)) : undefined,
      },
    },
  };
}

/** PRF-only assertion right after creation; the signature is discarded, so a client-generated challenge is fine. */
async function evalPrfViaGet(credentialId: ArrayBuffer): Promise<ArrayBuffer> {
  let cred: PublicKeyCredential | null = null;
  try {
    cred = (await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)) as BufferSource,
        allowCredentials: [{ type: 'public-key', id: credentialId }],
        userVerification: 'required',
        extensions: PRF_EXTENSION as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential | null;
  } catch {
    // fall through to the error below
  }
  const prf = cred ? prfExtension(cred).results?.first : undefined;
  if (!prf) throw new PasskeyError(NO_PRF_SUPPORT_MESSAGE);
  return prf;
}

function describeWebAuthnError(err: unknown, op: 'create' | 'get'): string {
  if (err instanceof DOMException) {
    if (err.name === 'NotAllowedError') return 'The passkey prompt was cancelled or timed out.';
    if (err.name === 'InvalidStateError' && op === 'create') {
      return 'A passkey for this account already exists on this device.';
    }
    if (err.name === 'SecurityError') return 'Passkeys require a secure context (HTTPS or localhost).';
  }
  return `Passkey ${op === 'create' ? 'creation' : 'sign-in'} failed: ${String(err)}`;
}

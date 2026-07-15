import type {
  AuthenticationResponsePayload,
  CreationOptionsJSON,
  RegistrationResponsePayload,
  RequestOptionsJSON,
} from './webauthn';

export interface NoteRecord {
  id: string;
  ciphertext: string;
  version: number;
  created_at: number;
  updated_at: number;
}

export class ApiError extends Error {
  status: number;
  body: Record<string, unknown>;

  constructor(status: number, body: Record<string, unknown>) {
    super(typeof body.error === 'string' ? body.error : `Request failed (${status})`);
    this.status = status;
    this.body = body;
  }
}

// Lets the vault lock itself when the server session expires mid-use, so
// crypto access and API access end together.
let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(fn: (() => void) | null) {
  onUnauthorized = fn;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: init?.body ? { 'Content-Type': 'application/json' } : undefined,
    ...init,
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    if (res.status === 401) onUnauthorized?.();
    throw new ApiError(res.status, body);
  }
  return body as T;
}

const post = <T>(path: string, payload?: object) =>
  request<T>(path, { method: 'POST', body: payload ? JSON.stringify(payload) : '{}' });

export const api = {
  // auth
  registerOptions: (username: string) => post<CreationOptionsJSON>('/api/auth/register/options', { username }),
  registerVerify: (payload: { response: RegistrationResponsePayload; prfSalt: string; wrappedMk: string }) =>
    post<{ ok: true; username: string }>('/api/auth/register/verify', payload),
  loginOptions: () => post<RequestOptionsJSON>('/api/auth/login/options'),
  loginVerify: (payload: { response: AuthenticationResponsePayload }) =>
    post<{ username: string; credentialId: string; wrappedMk: string; prfSalt: string }>(
      '/api/auth/login/verify',
      payload,
    ),
  recoverySetup: (payload: { verifier: string; wrappedMk: string }) =>
    post<{ ok: true }>('/api/auth/recovery/setup', payload),
  recoveryRedeem: (payload: { username: string; verifier: string }) =>
    post<{ wrappedMk: string }>('/api/auth/recovery/redeem', payload),
  listCredentials: () =>
    request<{ credentials: { id: string; transports: string[]; created_at: number }[] }>('/api/auth/credentials'),
  deleteCredential: (id: string) =>
    request<{ ok: true }>(`/api/auth/credentials/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  rotate: (payload: {
    credentialId: string;
    wrappedMk: string;
    recovery: { verifier: string; wrappedMk: string };
    notes: { id: string; ciphertext: string; version: number }[];
  }) => post<{ ok: true }>('/api/auth/rotate', payload),
  credentialsOptions: () => post<CreationOptionsJSON>('/api/auth/credentials/options'),
  credentialsVerify: (payload: { response: RegistrationResponsePayload; prfSalt: string; wrappedMk: string }) =>
    post<{ ok: true }>('/api/auth/credentials/verify', payload),
  logout: () => post<{ ok: true }>('/api/auth/logout'),

  // notes
  listNotes: () => request<{ notes: NoteRecord[] }>('/api/notes'),
  createNote: (id: string, ciphertext: string) =>
    post<{ id: string; version: number; created_at: number; updated_at: number }>('/api/notes', { id, ciphertext }),
  updateNote: (id: string, ciphertext: string, version: number) =>
    request<{ id: string; version: number; updated_at: number }>(`/api/notes/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ ciphertext, version }),
    }),
  deleteNote: (id: string) => request<{ ok: true }>(`/api/notes/${id}`, { method: 'DELETE' }),
};

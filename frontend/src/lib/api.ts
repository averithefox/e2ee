import { messages } from 'generated/messages';
import { err, ok, Result } from 'neverthrow';
import { randomBytes, xeddsa_sign } from './crypto';
import { db, type PqkemPreKey } from './db';
import { genInitKeyBundle } from './protocol';
import { b64Encode, type EnhancedOmit } from './utils';

export const API_BASE_URL = process.env.NODE_ENV === 'development' ? 'http://localhost:8000' : window.location.origin;

export async function fetch(url: string, { method = 'GET', ...rest }: RequestInit & { body?: Uint8Array | null } = {}) {
  const identity = await db.identity.limit(1).first();
  if (!identity)
    return window.fetch(url, {
      ...rest,
      method
    });

  const urlObj = new URL(url);
  const pathname = urlObj.pathname;
  const query = urlObj.search.slice(1); // Remove leading '?'

  // method + uri + query + body
  const methodBytes = new TextEncoder().encode(method.toUpperCase());
  const uriBytes = new TextEncoder().encode(pathname);
  const queryBytes = new TextEncoder().encode(query);
  const bodyBytes = rest.body ?? new Uint8Array(0);

  const messageParts = [methodBytes, uriBytes, queryBytes, bodyBytes];
  const totalLength = messageParts.reduce((sum, part) => sum + part.length, 0);
  const message = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of messageParts) {
    message.set(part, offset);
    offset += part.length;
  }

  const signature = xeddsa_sign(identity.priv, message, randomBytes(64));
  const signatureB64 = b64Encode(signature);

  const headers = new Headers(rest.headers);
  headers.set('X-Identity', identity.handle);
  headers.set('X-Signature', signatureB64);

  return window.fetch(url, { ...rest, method, headers });
}

type LimitedRequestInit = Omit<RequestInit, 'body' | 'method'>;

export async function registerIdentity(handle: string) {
  const keys = await genInitKeyBundle();

  const created_at = Date.now();
  const prekeyId = await db.prekeys.add({ priv: keys.prekey.secretKey, pub: keys.prekey.publicKey, created_at });
  const pqkemPrekeyId = await db.pqkem_prekeys.add({
    priv: keys.pqkemPrekey.secretKey,
    pub: keys.pqkemPrekey.publicKey,
    one_time: false,
    created_at
  } satisfies EnhancedOmit<PqkemPreKey, 'id'> as any);
  const oneTimePqkemPrekeyIds = await db.pqkem_prekeys.bulkAdd(
    keys.oneTimePqkemPrekeys.map(
      pqopk =>
        ({ priv: pqopk.secretKey, pub: pqopk.publicKey, one_time: true }) satisfies EnhancedOmit<
          PqkemPreKey,
          'id'
        > as any
    ),
    { allKeys: true }
  );
  const oneTimePrekeyIds = await db.one_time_prekeys.bulkAdd(
    keys.oneTimePrekeys.map(opk => ({ priv: opk.secretKey, pub: opk.publicKey, created_at })),
    { allKeys: true }
  );

  const pb = new messages.Identity({
    handle,
    id_key: keys.idKey.publicKey,
    prekey: new messages.SignedPrekey({
      key: keys.prekey.publicKey,
      id: prekeyId,
      sig: xeddsa_sign(keys.idKey.secretKey, keys.prekey.publicKey, randomBytes(64))
    }),
    pqkem_prekey: new messages.SignedPrekey({
      key: keys.pqkemPrekey.publicKey,
      id: pqkemPrekeyId,
      sig: xeddsa_sign(keys.idKey.secretKey, keys.pqkemPrekey.publicKey, randomBytes(64))
    }),
    one_time_pqkem_prekeys: keys.oneTimePqkemPrekeys.map(
      (pqopk, i) =>
        new messages.SignedPrekey({
          key: pqopk.publicKey,
          id: oneTimePqkemPrekeyIds[i]!,
          sig: xeddsa_sign(keys.idKey.secretKey, pqopk.publicKey, randomBytes(64))
        })
    ),
    one_time_prekeys: keys.oneTimePrekeys.map(
      (opk, i) =>
        new messages.Prekey({
          key: opk.publicKey,
          id: oneTimePrekeyIds[i]!
        })
    )
  });

  const buf = pb.serialize();

  const res = await window.fetch(`${API_BASE_URL}/api/identity`, {
    method: 'POST',
    body: buf
  });

  if (!res.ok) {
    await db.prekeys.delete(prekeyId);
    await db.pqkem_prekeys.bulkDelete([pqkemPrekeyId, ...oneTimePqkemPrekeyIds]);
    await db.one_time_prekeys.bulkDelete(oneTimePrekeyIds);
    throw new Error(res.statusText);
  }

  await db.identity.add({ handle, priv: keys.idKey.secretKey, pub: keys.idKey.publicKey });
}

export async function patchIdentity(
  patch: Partial<Exclude<ConstructorParameters<typeof messages.IdentityPatch>[0] & {}, any[]>>
) {
  const pb = new messages.IdentityPatch({
    ...patch,
    one_time_pqkem_prekeys: patch.one_time_pqkem_prekeys ?? [],
    one_time_prekeys: patch.one_time_prekeys ?? []
  });
  const buf = pb.serialize();
  const res = await window.fetch(`${API_BASE_URL}/api/identity`, {
    method: 'PATCH',
    body: buf
  });
  if (!res.ok) {
    throw new Error(res.statusText);
  }
}

export async function fetchKeyBundle(
  handle: string,
  requestInit?: LimitedRequestInit,
  dryRun?: boolean
): Promise<Result<messages.PQXDHKeyBundle, number>> {
  const res = await fetch(`${API_BASE_URL}/api/keys/${handle}/bundle${dryRun ? '?dryRun=1' : ''}`, requestInit);
  if (!res.ok) return err(res.status);
  const buf = await res.arrayBuffer();
  return ok(messages.PQXDHKeyBundle.deserialize(new Uint8Array(buf)));
}

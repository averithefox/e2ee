import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { messages } from 'generated/messages';
import { secret } from 'generated/secret';
import { websocket } from 'generated/websocket';
import sodium from 'libsodium-wrappers';
import { MlKem1024 } from 'mlkem';
import { fetchKeyBundle } from './api';
import { xeddsa_verify } from './crypto';
import { db, type Session } from './db';
import { b64Encode, concat, type ResultPromise } from './utils';

const PQXDH_INFO = new TextEncoder().encode('me.averi.chat_CURVE25519_SHA-512_ML-KEM-1024');
const KDF_RK_INFO = new TextEncoder().encode('me.averi.chat_DoubleRatchet_RootKey');
const MAX_SKIP = 1000;

export const genCurveKeyPair = x25519.keygen;

const kem = new MlKem1024();
export async function genPqkemKeyPair() {
  const [publicKey, secretKey] = await kem.generateKeyPair();
  return { publicKey, secretKey };
}

export async function genInitKeyBundle() {
  const idKey = genCurveKeyPair();
  const prekey = genCurveKeyPair();
  const pqkemPrekey = await genPqkemKeyPair();
  const oneTimePqkemPrekeys = await Promise.all(Array.from({ length: 100 }, genPqkemKeyPair));
  const oneTimePrekeys = Array.from({ length: 100 }, genCurveKeyPair);

  return {
    idKey,
    prekey,
    pqkemPrekey,
    oneTimePqkemPrekeys,
    oneTimePrekeys
  };
}

export type KeyBundle = Exclude<Awaited<ReturnType<typeof genInitKeyBundle>>, 'nextId'>;

export const DH = x25519.getSharedSecret;

function KDF_PQXDH(KM: Uint8Array) {
  const F = new Uint8Array(32).fill(0xff);
  const input = concat(F, KM);
  const salt = new Uint8Array(sha512.outputLen).fill(0);
  return hkdf(sha512, input, salt, PQXDH_INFO, 32);
}

function KDF_RK(rk: Uint8Array, dh_out: Uint8Array): [Uint8Array, Uint8Array] {
  const result = hkdf(sha256, dh_out, rk, KDF_RK_INFO, 64);
  return [result.slice(0, 32), result.slice(32, 64)];
}

function KDF_CK(ck: Uint8Array): [Uint8Array, Uint8Array] {
  const mk = hmac(sha256, ck, new Uint8Array([0x01]));
  const next_ck = hmac(sha256, ck, new Uint8Array([0x02]));
  return [next_ck, mk];
}

async function encrypt(session: Session, plaintext: Uint8Array, AD: Uint8Array) {
  const [next_ck, mk] = KDF_CK(session.CKs!);
  session.CKs = next_ck;

  const info = new TextEncoder().encode('me.averi.chat_MessageKey');
  const derived = hkdf(sha256, mk, new Uint8Array(0), info, 56);
  const key = derived.slice(0, 32);
  const nonce = derived.slice(32, 56);

  await sodium.ready;
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, AD, null, nonce, key);

  const header = new websocket.MessageHeader({
    dh_public_key: session.DHs_pub,
    previous_chain_len: session.PN,
    message_number: session.Ns++
  });

  return { header, ciphertext, nonce };
}

async function trySkipMessageKeys(session: Session, until: number) {
  if (session.Nr + MAX_SKIP < until) throw new Error('Too many skipped messages');
  if (session.CKr) {
    while (session.Nr < until) {
      const [next_ck, mk] = KDF_CK(session.CKr);
      session.CKr = next_ck;
      await db.skipped_message_keys.add({
        session_id: session.id,
        dh_public_key: session.DHr!,
        message_number: session.Nr,
        value: mk
      });
      session.Nr++;
    }
  }
}

function ratchetStep(session: Session, header: websocket.MessageHeader) {
  session.PN = session.Ns;
  session.Ns = 0;
  session.Nr = 0;
  session.DHr = header.dh_public_key;
  [session.RK, session.CKr] = KDF_RK(session.RK, DH(session.DHs_priv, session.DHr));
  const DHs = genCurveKeyPair();
  [session.DHs_priv, session.DHs_pub] = [DHs.secretKey, DHs.publicKey];
  [session.RK, session.CKs] = KDF_RK(session.RK, DH(session.DHs_priv, session.DHr));
}

async function decrypt(
  session: Session,
  header: websocket.MessageHeader,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  AD: Uint8Array
) {
  let mk = await db.skipped_message_keys
    .where({ session_id: session.id, dh_public_key: header.dh_public_key, message_number: header.message_number })
    .first();
  let mkValue = mk?.value;

  if (mk && mkValue) {
    await db.skipped_message_keys.delete(mk.id);
  } else {
    if (session.DHr === null || b64Encode(header.dh_public_key) !== b64Encode(session.DHr)) {
      await trySkipMessageKeys(session, header.previous_chain_len);
      ratchetStep(session, header);
    }
    await trySkipMessageKeys(session, header.message_number);
    const [next_ck, message_mk] = KDF_CK(session.CKr!);
    session.CKr = next_ck;
    session.Nr++;
    mkValue = message_mk;
  }

  const info = new TextEncoder().encode('me.averi.chat_MessageKey');
  const derived = hkdf(sha256, mkValue, new Uint8Array(0), info, 56);
  const key = derived.slice(0, 32);

  await sodium.ready;
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, AD, nonce, key);
}

export function verifyKeyBundle(bundle: messages.PQXDHKeyBundle, idKeyOverride?: Uint8Array) {
  const idKey = idKeyOverride ?? bundle.id_key;
  return (
    xeddsa_verify(idKey, bundle.prekey.key, bundle.prekey.sig) &&
    xeddsa_verify(idKey, bundle.pqkem_prekey.key, bundle.pqkem_prekey.sig)
  );
}

export async function sendMessage(
  to: string,
  payload: secret.Payload,
  {
    keyBundleProvider,
    session
  }: {
    keyBundleProvider?: (handle: string) => ResultPromise<messages.PQXDHKeyBundle, any>;
    session?: Session | null;
  } = {}
) {
  const identity = await db.identity.limit(1).first();
  if (!identity) {
    throw new Error('no identity found');
  }

  const encoder = new TextEncoder();
  if (session === undefined) {
    session = await db.sessions.where({ peer: to }).first();
  }

  if (!session) {
    const res = await (keyBundleProvider ?? fetchKeyBundle)(to);
    if (res.isErr()) {
      throw new Error('failed to fetch key bundle');
    }
    const bundle = res.value;

    if (!bundle.has_prekey || !bundle.has_pqkem_prekey) {
      throw new Error('incomplete key bundle');
    }

    if (!verifyKeyBundle(bundle)) {
      throw new Error('signature verification failed');
    }

    const EK = genCurveKeyPair();

    const [CT, SS] = await kem.encap(bundle.pqkem_prekey.key);

    const DH1 = DH(identity.priv, bundle.prekey.key);
    const DH2 = DH(EK.secretKey, bundle.id_key);
    const DH3 = DH(EK.secretKey, bundle.prekey.key);
    const DH4 = bundle.has_one_time_prekey ? DH(EK.secretKey, bundle.one_time_prekey.key) : new Uint8Array(0);
    const SK = KDF_PQXDH(concat(DH1, DH2, DH3, DH4, SS));

    const DHs = genCurveKeyPair();

    session = {
      peer: to,
      RK: SK,
      DHs_priv: DHs.secretKey,
      DHs_pub: DHs.publicKey,
      DHr: bundle.prekey.key,
      CKs: null,
      CKr: null,
      Ns: 0,
      Nr: 0,
      PN: 0
    } satisfies Omit<Session, 'id'> as Session;
    [session.RK, session.CKs] = KDF_RK(session.RK, DH(session.DHs_priv, session.DHr!));
    session.id = await db.sessions.add(session);

    const AD = concat(identity.pub, bundle.id_key, encoder.encode(identity.handle), encoder.encode(to));
    const { header, ciphertext, nonce } = await encrypt(session, payload.serialize(), AD);

    await db.sessions.put(session);

    return {
      forward: new websocket.Forward({
        handle: to,
        pqxdh_init: new websocket.PQXDHInit({
          id_key: identity.pub,
          ephemeral_key: EK.publicKey,
          pqkem_ciphertext: CT,
          prekey_ids: [
            bundle.prekey.id,
            bundle.pqkem_prekey.id,
            ...(bundle.has_one_time_prekey ? [bundle.one_time_prekey.id] : [])
          ],
          initial_message: new websocket.EncryptedMessage({
            header,
            ciphertext,
            nonce
          })
        })
      }),
      session
    };
  } else {
    const AD = encoder.encode(identity.handle + to);
    const encrypted = await encrypt(session, payload.serialize(), AD);
    return {
      forward: new websocket.Forward({
        handle: to,
        message: new websocket.EncryptedMessage(encrypted)
      }),
      session
    };
  }
}

export async function recvMessage(pb: websocket.Forward) {
  const identity = await db.identity.limit(1).first();
  if (!identity) {
    throw new Error('No identity found');
  }

  const encoder = new TextEncoder();
  if (pb.payload === 'pqxdh_init') {
    const msg = pb.pqxdh_init;

    const [SPKId, PQPKId, OPKId] = msg.prekey_ids;
    if (!SPKId || !PQPKId) {
      throw new Error('Missing prekey IDs');
    }

    const SPK = await db.prekeys.get(SPKId);
    if (!SPK) {
      throw new Error(`unable to find a prekey with id ${SPKId}`);
    }

    const PQPK = await db.pqkem_prekeys.get(PQPKId);
    if (!PQPK) {
      throw new Error(`unable to find a pqkem prekey with id ${PQPKId}`);
    } else if (PQPK.one_time) {
      await db.pqkem_prekeys.delete(PQPK.id);
    }

    const OPK = OPKId ? await db.one_time_prekeys.get(OPKId) : null;
    if (OPKId && !OPK) {
      throw new Error(`unable to find a one-time prekey with id ${OPKId}`);
    }

    const SS = await kem.decap(msg.pqkem_ciphertext, PQPK.priv);

    const DH1 = DH(SPK.priv, msg.id_key);
    const DH2 = DH(identity.priv, msg.ephemeral_key);
    const DH3 = DH(SPK.priv, msg.ephemeral_key);
    const DH4 = OPK ? DH(OPK.priv, msg.ephemeral_key) : new Uint8Array(0);
    const SK = KDF_PQXDH(concat(DH1, DH2, DH3, DH4, SS));

    const session = {
      peer: pb.handle,
      RK: SK,
      DHs_priv: SPK.priv,
      DHs_pub: SPK.pub,
      DHr: null,
      CKs: null,
      CKr: null,
      Ns: 0,
      Nr: 0,
      PN: 0
    } satisfies Omit<Session, 'id'> as Session;
    session.id = await db.sessions.add(session);

    const AD = concat(msg.id_key, identity.pub, encoder.encode(pb.handle), encoder.encode(identity.handle));

    const plaintext = await decrypt(
      session,
      msg.initial_message.header,
      msg.initial_message.ciphertext,
      msg.initial_message.nonce,
      AD
    );

    await db.sessions.put(session);

    return { payload: secret.Payload.deserialize(plaintext), session };
  } else if (pb.payload === 'message') {
    const session = await db.sessions.where({ peer: pb.handle }).first();
    if (!session) throw new Error('No session');
    const msg = pb.message;
    const AD = encoder.encode(pb.handle + identity.handle);
    const plaintext = await decrypt(session, msg.header, msg.ciphertext, msg.nonce, AD);
    return { payload: secret.Payload.deserialize(plaintext), session };
  } else {
    throw new Error('unknown payload');
  }
}

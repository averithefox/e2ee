import Dexie, { type EntityTable } from 'dexie';

interface X25519KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

interface SignedKey extends X25519KeyPair {
  id: number;
  sig: Uint8Array;
}

interface PQKey {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  id: number;
  sig: Uint8Array;
}

interface OneTimeKey extends X25519KeyPair {
  id: number;
}

// DB record types (with required primary keys)
interface IdentityKeyRecord extends X25519KeyPair {
  type: 'IK';
}

interface SignedPreKeyRecord extends SignedKey {
  type: 'SPK';
}

interface PQPreSharedKeyRecord extends PQKey {
  type: 'PQPSK';
}

interface MetadataRecord {
  key: string;
  value: string | number;
}

export interface KeyBundle {
  IK: X25519KeyPair;
  SPK: SignedKey;
  PQPSK: PQKey;
  OPKs: OneTimeKey[];
  PQOPKs: PQKey[];
  nextKeyId: number;
}

const db = new Dexie('chat_averi_keys') as Dexie & {
  identityKeys: EntityTable<IdentityKeyRecord, 'type'>;
  signedPreKeys: EntityTable<SignedPreKeyRecord, 'type'>;
  pqPreSharedKeys: EntityTable<PQPreSharedKeyRecord, 'type'>;
  oneTimeKeys: EntityTable<OneTimeKey, 'id'>;
  pqOneTimeKeys: EntityTable<PQKey, 'id'>;
  metadata: EntityTable<MetadataRecord, 'key'>;
};

db.version(1).stores({
  identityKeys: 'type',
  signedPreKeys: 'type',
  pqPreSharedKeys: 'type',
  oneTimeKeys: 'id',
  pqOneTimeKeys: 'id',
  metadata: 'key'
});

export async function storeKeys(bundle: KeyBundle): Promise<void> {
  await db.transaction(
    'rw',
    [db.identityKeys, db.signedPreKeys, db.pqPreSharedKeys, db.oneTimeKeys, db.pqOneTimeKeys, db.metadata],
    async () => {
      // Clear existing keys
      await Promise.all([
        db.identityKeys.clear(),
        db.signedPreKeys.clear(),
        db.pqPreSharedKeys.clear(),
        db.oneTimeKeys.clear(),
        db.pqOneTimeKeys.clear()
      ]);

      // Store identity key
      await db.identityKeys.put({
        type: 'IK',
        publicKey: bundle.IK.publicKey,
        privateKey: bundle.IK.privateKey
      });

      // Store signed pre-key
      await db.signedPreKeys.put({
        type: 'SPK',
        id: bundle.SPK.id,
        publicKey: bundle.SPK.publicKey,
        privateKey: bundle.SPK.privateKey,
        sig: bundle.SPK.sig
      });

      // Store PQ pre-shared key
      await db.pqPreSharedKeys.put({
        type: 'PQPSK',
        id: bundle.PQPSK.id,
        publicKey: bundle.PQPSK.publicKey,
        privateKey: bundle.PQPSK.privateKey,
        sig: bundle.PQPSK.sig
      });

      // Store one-time keys
      if (bundle.OPKs.length > 0) {
        await db.oneTimeKeys.bulkPut(bundle.OPKs);
      }

      // Store PQ one-time keys
      if (bundle.PQOPKs.length > 0) {
        await db.pqOneTimeKeys.bulkPut(bundle.PQOPKs);
      }

      // Store nextKeyId
      await db.metadata.put({ key: 'nextKeyId', value: bundle.nextKeyId });
    }
  );
}

export async function loadKeys(): Promise<KeyBundle | null> {
  const [ik, spk, pqpsk, opks, pqopks, nextKeyIdRecord] = await Promise.all([
    db.identityKeys.get('IK'),
    db.signedPreKeys.get('SPK'),
    db.pqPreSharedKeys.get('PQPSK'),
    db.oneTimeKeys.toArray(),
    db.pqOneTimeKeys.toArray(),
    db.metadata.get('nextKeyId')
  ]);

  if (!ik || !spk || !pqpsk) return null;

  return {
    IK: { publicKey: ik.publicKey, privateKey: ik.privateKey },
    SPK: { id: spk.id, publicKey: spk.publicKey, privateKey: spk.privateKey, sig: spk.sig },
    PQPSK: { id: pqpsk.id, publicKey: pqpsk.publicKey, privateKey: pqpsk.privateKey, sig: pqpsk.sig },
    OPKs: opks,
    PQOPKs: pqopks,
    nextKeyId: (nextKeyIdRecord?.value as number) ?? 0
  };
}

export async function deleteKeys(): Promise<void> {
  await db.transaction(
    'rw',
    [db.identityKeys, db.signedPreKeys, db.pqPreSharedKeys, db.oneTimeKeys, db.pqOneTimeKeys, db.metadata],
    async () => {
      await Promise.all([
        db.identityKeys.clear(),
        db.signedPreKeys.clear(),
        db.pqPreSharedKeys.clear(),
        db.oneTimeKeys.clear(),
        db.pqOneTimeKeys.clear(),
        db.metadata.delete('nextKeyId')
      ]);
    }
  );
}

export async function storeHandle(handle: string): Promise<void> {
  await db.metadata.put({ key: 'handle', value: handle });
}

export async function loadHandle(): Promise<string | null> {
  const record = await db.metadata.get('handle');
  return (record?.value as string) ?? null;
}

export async function deleteHandle(): Promise<void> {
  await db.metadata.delete('handle');
}

export async function consumeOPK(id: number): Promise<OneTimeKey | null> {
  const opk = await db.oneTimeKeys.get(id);
  if (!opk) return null;

  await db.oneTimeKeys.delete(id);
  return opk;
}

export async function consumePQOPK(id: number): Promise<PQKey | null> {
  const pqopk = await db.pqOneTimeKeys.get(id);
  if (!pqopk) return null;

  await db.pqOneTimeKeys.delete(id);
  return pqopk;
}

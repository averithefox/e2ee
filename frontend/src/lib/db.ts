import { Dexie, type EntityTable } from 'dexie';

export interface IdKey {
  for: string;
  pub: Uint8Array;
}

export interface Key {
  id: number;
  priv: Uint8Array;
  pub: Uint8Array;
}

export interface Identity {
  id: number;
  handle: string;
  priv: Uint8Array;
  pub: Uint8Array;
}

export interface Session {
  id: number;
  peer: string;
  RK: Uint8Array;
  CKs: Uint8Array | null;
  CKr: Uint8Array | null;
  DHs_priv: Uint8Array;
  DHs_pub: Uint8Array;
  DHr: Uint8Array | null;
  Ns: number;
  Nr: number;
  PN: number;
}

export interface SkippedMessageKeys {
  id: number;
  session_id: number;
  dh_public_key: Uint8Array;
  message_number: number;
  value: Uint8Array;
}

export interface StoredMessage {
  id: number;
  peer: string;
  sender: string;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

export const db = new Dexie('theDb') as Dexie & {
  identity: EntityTable<Identity, 'id'>;
  identity_keys: EntityTable<IdKey, 'for'>;
  prekeys: EntityTable<Key, 'id'>;
  pqkem_prekeys: EntityTable<Key & { oneTime: boolean }, 'id'>;
  one_time_prekeys: EntityTable<Key, 'id'>;
  sessions: EntityTable<Session, 'id'>;
  skipped_message_keys: EntityTable<SkippedMessageKeys, 'id'>;
  messages: EntityTable<StoredMessage, 'id'>;
};

db.version(1).stores({
  identity: '++id,&handle',
  identity_keys: '&for',
  prekeys: '++id',
  pqkem_prekeys: '++id',
  one_time_prekeys: '++id',
  sessions: '++id,peer',
  skipped_message_keys: '++id,[session_id+dh_public_key+message_number]',
  messages: '++id,peer,sender'
});

if (process.env.NODE_ENV === 'development') {
  (window as any).db = db;
}

import { Dexie, type EntityTable } from 'dexie';

export interface IdKey {
  for: string;
  pub: Uint8Array;
}

export interface PreKey {
  id: number;
  priv: Uint8Array;
  pub: Uint8Array;
  created_at: number;
}

export type PqkemPreKey = (PreKey & { one_time: false }) | (Omit<PreKey, 'created_at'> & { one_time: true });

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

export interface Message {
  id: number;
  peer: string;
  sender: string;
  text: string | null;
  reply_to: Message['id'] | null;
  timestamp: number;
  last_edited_at: number | null;
  status: 'pending' | 'sent' | 'delivered' | 'seen';
}

export interface Attachment {
  id: number;
  sender: string;
  message_id: Message['id'];
  mime_type: string;
  data: Uint8Array;
}

export const db = new Dexie('theDb') as Dexie & {
  identity: EntityTable<Identity, 'id'>;
  identity_keys: EntityTable<IdKey, 'for'>;
  prekeys: EntityTable<PreKey, 'id'>;
  pqkem_prekeys: EntityTable<PqkemPreKey, 'id'>;
  one_time_prekeys: EntityTable<Omit<PreKey, 'created_at'>, 'id'>;
  sessions: EntityTable<Session, 'id'>;
  skipped_message_keys: EntityTable<SkippedMessageKeys, 'id'>;
  messages: EntityTable<Message>;
  attachments: EntityTable<Attachment>;
};

db.version(1).stores({
  identity: '++id,&handle',
  identity_keys: '&for',
  prekeys: '++id',
  pqkem_prekeys: '++id',
  one_time_prekeys: '++id',
  sessions: '++id,peer',
  skipped_message_keys: '++id,[session_id+dh_public_key+message_number]',
  messages: '++,&[id+peer],[id+sender],[id+peer+sender],id,peer,sender,reply_to',
  attachments: '++,&[id+sender+message_id],[sender+message_id],id,sender,message_id'
});

if (process.env.NODE_ENV === 'development') {
  (window as any).db = db;
}

import { useLiveQuery } from 'dexie-react-hooks';
import { messages as messages_proto } from 'generated/messages';
import { websocket } from 'generated/websocket';
import { err, ok, type Result } from 'neverthrow';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation } from 'wouter';
import { API_BASE_URL, fetchKeyBundle } from '~/lib/api';
import { randomBytes, xeddsa_sign } from '~/lib/crypto';
import { db } from '~/lib/db';
import { decryptLocal, encryptLocal, recvMessage, sendMessage } from '~/lib/protocol';
import { eq } from '~/lib/utils';

export type MessageData = {
  dbId: number;
  id: Uint8Array;
  sender: string;
  text: string | null;
  timestamp: number;
  editedAt: number | null;
  replyTo: Uint8Array | null;
};

type Identity = { handle: string; sigKey: Uint8Array };

export function useChat() {
  const [, navigate] = useLocation();
  const wsRef = useRef<(WebSocket & { msgId: number; connectAttempts: number }) | null>(null);

  const [status, setStatus] = useState<Result<string, string> | null>();
  const [identity, setIdentity] = useState<Identity>(null!);
  const [selectedContact, setSelectedContact] = useState<string | null>(null);

  // WebSocket send helper
  const send = useCallback(
    async (
      msg: Omit<Exclude<ConstructorParameters<typeof websocket.ServerboundMessage>[0] & {}, any[]>, 'id'>
    ): Promise<websocket.Ack.Error | null> => {
      const ws = wsRef.current;
      if (!ws) return websocket.Ack.Error.SERVER_ERROR;

      const id = ws.msgId++;
      const pb = new websocket.ServerboundMessage({
        ...msg,
        id
      } as ConstructorParameters<typeof websocket.ServerboundMessage>[0]);
      console.log('[WS] serverbound', pb.toObject());
      ws.send(pb.serialize());

      return new Promise(resolve => {
        ws.addEventListener('message', function cb(ev) {
          const msg = websocket.ClientboundMessage.deserialize(ev.data);
          if (msg.payload === 'ack' && msg.ack.message_id === id) {
            ws.removeEventListener('message', cb);
            resolve(msg.ack.has_error ? msg.ack.error : null);
          }
        });
      });
    },
    []
  );

  // Fetch key bundle helper
  const getKeyBundle = useCallback(async (handle: string) => {
    const keyBundle = await fetchKeyBundle(handle);
    if (keyBundle.isErr()) return keyBundle;
    const lastKnownIdKey = await db.identity_keys.get(handle);
    if (!lastKnownIdKey) return keyBundle;
    if (eq(keyBundle.value.id_key, lastKnownIdKey.pub)) return keyBundle;
    throw new Error('KEY_MISMATCH');
  }, []);

  // Handle incoming forward messages
  const onForwardPb = useCallback(async (msg: websocket.Forward) => {
    const payload = await recvMessage(msg);

    switch (payload.sync) {
      case 'edit_target': {
        const targetUuid = payload.edit_target;
        const newText = payload.text;
        const peerMessages = await db.messages.where({ peer: msg.handle }).toArray();

        for (const storedMsg of peerMessages) {
          const plaintext = await decryptLocal(storedMsg.ciphertext, storedMsg.nonce);
          const msgPayload = messages_proto.MessagePayload.deserialize(plaintext);
          if (eq(msgPayload.uuid, targetUuid)) {
            msgPayload.text = newText;
            msgPayload.edited_at = Date.now();
            const { ciphertext, nonce } = await encryptLocal(msgPayload.serialize());
            await db.messages.update(storedMsg.id, { ciphertext, nonce });
            return;
          }
        }
        return;
      }

      case 'delete_target': {
        const targetUuid = payload.delete_target;
        const peerMessages = await db.messages.where({ peer: msg.handle }).toArray();

        for (const storedMsg of peerMessages) {
          const plaintext = await decryptLocal(storedMsg.ciphertext, storedMsg.nonce);
          const msgPayload = messages_proto.MessagePayload.deserialize(plaintext);
          if (eq(msgPayload.uuid, targetUuid)) {
            await db.messages.delete(storedMsg.id);
            return;
          }
        }
        return;
      }

      case 'none':
      default: {
        const { ciphertext, nonce } = await encryptLocal(payload.serialize());
        await db.messages.add({
          peer: msg.handle,
          sender: msg.handle,
          ciphertext,
          nonce
        });
      }
    }
  }, []);

  // Initialize WebSocket connection
  useEffect(() => {
    (async () => {
      setStatus(ok('loading'));

      const identity = await db.identity.limit(1).first();
      if (!identity) {
        return navigate('/register');
      }
      setIdentity({ handle: identity.handle, sigKey: identity.pub });

      setStatus(ok('connecting'));

      const ws = new WebSocket(`${API_BASE_URL}/api/ws`) as NonNullable<typeof wsRef.current>;
      ws.msgId = 0;
      ws.connectAttempts = 0;
      ws.binaryType = 'arraybuffer';
      wsRef.current = ws;

      ws.onopen = () => {
        setStatus(ok('authenticating'));
      };

      ws.onmessage = ev => {
        const msg = websocket.ClientboundMessage.deserialize(ev.data);
        console.log('[WS] clientbound', msg.toObject());
        switch (msg.payload) {
          case 'challenge': {
            const id = ws.msgId++;
            const pb = new websocket.ServerboundMessage({
              id,
              challenge_response: new websocket.ChallengeResponse({
                handle: identity.handle,
                signature: xeddsa_sign(identity.priv, msg.challenge.nonce, randomBytes(64))
              })
            });
            ws.send(pb.serialize());

            ws.addEventListener('message', function cb(ev) {
              const ackMsg = websocket.ClientboundMessage.deserialize(ev.data);
              if (ackMsg.payload === 'ack' && ackMsg.ack.message_id === id) {
                ws.removeEventListener('message', cb);
                if (ackMsg.ack.has_error) {
                  setStatus(err(`server rejected authentication: ${websocket.Ack.Error[ackMsg.ack.error]}`));
                } else {
                  setStatus(null);
                }
              }
            });
            break;
          }
          case 'forward': {
            onForwardPb(msg.forward);
            break;
          }
        }
      };

      ws.onclose = () => {};
    })();
  }, [navigate, onForwardPb]);

  // Contacts list query
  const contacts = useLiveQuery(async () => {
    const messages = await db.messages.toArray();
    const peers = Array.from(new Set(messages.map(msg => msg.peer)));
    return Promise.all(
      peers.map(async handle => {
        const lastMessage = (await db.messages.where({ peer: handle }).last()) ?? null;
        if (!lastMessage) return { handle, lastMessage: null };
        const plaintext = await decryptLocal(lastMessage.ciphertext, lastMessage.nonce);
        const payload = messages_proto.MessagePayload.deserialize(plaintext);
        return {
          handle,
          lastMessage: {
            sender: lastMessage.sender,
            text: payload.text ?? ''
          }
        };
      })
    );
  });

  const contactsList = useMemo(() => {
    const list = [...(contacts ?? [])];
    if (selectedContact && !contacts?.some(c => c.handle === selectedContact)) {
      list.push({ handle: selectedContact, lastMessage: null });
    }
    return list;
  }, [contacts, selectedContact]);

  // Messages query for selected contact
  const messages = useLiveQuery(async (): Promise<MessageData[]> => {
    if (!selectedContact) return [];
    const messages = await db.messages.where({ peer: selectedContact }).toArray();
    const decrypted = await Promise.all(
      messages.map(async ({ id: dbId, sender, ciphertext, nonce }): Promise<MessageData> => {
        const plaintext = await decryptLocal(ciphertext, nonce);
        const payload = messages_proto.MessagePayload.deserialize(plaintext);
        return {
          dbId,
          id: payload.uuid,
          sender,
          text: payload.has_text ? payload.text : null,
          timestamp: payload.timestamp,
          editedAt: payload.has_edited_at ? payload.edited_at : null,
          replyTo: payload.has_reply_to ? payload.reply_to : null
        };
      })
    );
    return decrypted.sort((a, b) => a.timestamp - b.timestamp);
  }, [selectedContact]);

  // Send a new message
  const sendNewMessage = useCallback(
    async (text: string, replyTo?: Uint8Array) => {
      if (!selectedContact || !text.trim()) return false;

      const payload = new messages_proto.MessagePayload({
        uuid: randomBytes(16),
        text: text.trim(),
        attachments: [],
        timestamp: Date.now(),
        ...(replyTo && { reply_to: replyTo })
      });

      const forward = await sendMessage(selectedContact, payload, getKeyBundle);
      const error = await send({ forward });

      if (error) {
        console.error(error);
        return false;
      }

      const { ciphertext, nonce } = await encryptLocal(payload.serialize());
      await db.messages.add({
        peer: selectedContact,
        sender: identity.handle,
        ciphertext,
        nonce
      });

      return true;
    },
    [selectedContact, identity, send, getKeyBundle]
  );

  // Edit a message
  const editMessage = useCallback(
    async (msg: MessageData, newText: string) => {
      if (!selectedContact || !newText.trim()) return false;

      const storedMsg = await db.messages.get(msg.dbId);
      if (!storedMsg) return false;

      const plaintext = await decryptLocal(storedMsg.ciphertext, storedMsg.nonce);
      const payload = messages_proto.MessagePayload.deserialize(plaintext);
      payload.text = newText.trim();
      payload.edited_at = Date.now();

      const { ciphertext, nonce } = await encryptLocal(payload.serialize());
      await db.messages.update(msg.dbId, { ciphertext, nonce });

      // Send sync message
      const syncPayload = new messages_proto.MessagePayload({
        uuid: randomBytes(16),
        timestamp: Date.now(),
        attachments: [],
        edit_target: msg.id,
        text: newText.trim()
      });

      const forward = await sendMessage(selectedContact, syncPayload, getKeyBundle);
      await send({ forward });

      return true;
    },
    [selectedContact, send, getKeyBundle]
  );

  // Delete a message
  const deleteMessage = useCallback(
    async (msg: MessageData) => {
      if (!selectedContact) return false;

      await db.messages.delete(msg.dbId);

      // Send sync message
      const syncPayload = new messages_proto.MessagePayload({
        uuid: randomBytes(16),
        timestamp: Date.now(),
        attachments: [],
        delete_target: msg.id
      });

      const forward = await sendMessage(selectedContact, syncPayload, getKeyBundle);
      await send({ forward });

      return true;
    },
    [selectedContact, send, getKeyBundle]
  );

  return {
    status,
    identity,
    selectedContact,
    setSelectedContact,
    contactsList,
    messages,
    sendNewMessage,
    editMessage,
    deleteMessage
  };
}

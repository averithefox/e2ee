import { useLiveQuery } from 'dexie-react-hooks';
import { secret } from 'generated/secret';
import { websocket } from 'generated/websocket';
import { err, ok, type Result } from 'neverthrow';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { toast } from 'sonner';
import { useLocation } from 'wouter';
import { API_BASE_URL, fetchKeyBundle } from '~/lib/api';
import { randomBytes, xeddsa_sign } from '~/lib/crypto';
import { db, type Message } from '~/lib/db';
import { recvMessage, sendMessage } from '~/lib/protocol';
import { eq } from '~/lib/utils';

type Identity = { handle: string; sigKey: Uint8Array };

export function useChat() {
  const [, navigate] = useLocation();
  const wsRef = useRef<WebSocket | null>(null);
  const wsMsgIdRef = useRef(0);

  const [status, setStatus] = useState<Result<string, string> | null>();
  const [identity, setIdentity] = useState<Identity>(null!);
  const [selectedContact, setSelectedContact] = useState<string | null>(null);

  const send = useCallback(
    async (
      msg: Omit<Exclude<ConstructorParameters<typeof websocket.ServerboundMessage>[0] & {}, any[]>, 'id'>
    ): Promise<websocket.Ack.Error | null> => {
      const ws = wsRef.current;
      if (!ws) return websocket.Ack.Error.SERVER_ERROR;

      const id = wsMsgIdRef.current++;
      const pb = new websocket.ServerboundMessage({
        ...msg,
        id
      } as ConstructorParameters<typeof websocket.ServerboundMessage>[0]);
      console.log('[WS] ->', pb.toObject());
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

  const getKeyBundle = useCallback(async (handle: string) => {
    const keyBundle = await fetchKeyBundle(handle);
    if (keyBundle.isErr()) return keyBundle;
    const lastKnownIdKey = await db.identity_keys.get(handle);
    if (!lastKnownIdKey) return keyBundle;
    if (eq(keyBundle.value.id_key, lastKnownIdKey.pub)) return keyBundle;
    throw new Error('KEY_MISMATCH');
  }, []);

  const onForwardPb = useCallback(async (pb: websocket.Forward) => {
    const { payload, session } = await recvMessage(pb);

    console.log('[WS] <-', payload.toObject());

    switch (payload.type) {
      case 'msg_new': {
        const msg = payload.msg_new;
        await db.messages.add({
          id: msg.id,
          peer: pb.handle,
          sender: pb.handle,
          text: msg.has_text ? msg.text : null,
          reply_to: msg.has_reply_to ? msg.reply_to : null,
          timestamp: msg.timestamp,
          last_edited_at: null,
          status: 'seen' // by the time you'll see the indicator, the message itself has been seen
        });
        await db.attachments.bulkAdd(
          msg.attachments.map(attachment => ({
            id: attachment.id,
            sender: pb.handle,
            message_id: msg.id,
            mime_type: attachment.mime_type,
            data: attachment.data
          }))
        );
        await sendMessage(
          pb.handle,
          new secret.Payload({
            receipt: new secret.Receipt({
              [pb.handle === selectedContact && document.hasFocus() ? 'seen' : 'received']: msg.id
            })
          }),
          { session }
        ).then(send);
        break;
      }

      case 'msg_edit': {
        const edit = payload.msg_edit;
        await db.messages.where({ sender: pb.handle, id: edit.id }).modify(msg => {
          msg.text = edit.has_text ? edit.text : null;
          msg.last_edited_at = edit.timestamp;
        });
        await db.attachments
          .where({ sender: pb.handle, message_id: edit.id, id: { in: edit.attachment_ids } })
          .delete();
        await sendMessage(
          pb.handle,
          new secret.Payload({
            receipt: new secret.Receipt({
              [pb.handle === selectedContact && document.hasFocus() ? 'seen' : 'received']: edit.id
            })
          }),
          { session }
        ).then(send);
        break;
      }

      case 'msg_delete': {
        const del = payload.msg_delete;
        await db.messages.where({ sender: pb.handle, id: del.id }).delete();
        await db.attachments.where({ sender: pb.handle, message_id: del.id }).delete();
        break;
      }

      case 'receipt': {
        const receipt = payload.receipt;
        switch (receipt.type) {
          case 'received': {
            await db.messages.where({ peer: pb.handle, id: receipt.received }).modify(msg => {
              msg.status = 'delivered';
            });
            break;
          }
          case 'seen': {
            await db.messages.where({ peer: pb.handle, id: receipt.seen }).modify(msg => {
              msg.status = 'seen';
            });
            break;
          }
        }
        break;
      }

      default: {
        toast.warning(`Received payload of unknown type: ${payload.type}`);
        break;
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
      ws.binaryType = 'arraybuffer';
      wsRef.current = ws;

      ws.onopen = () => {
        setStatus(ok('authenticating'));
      };

      ws.onmessage = ev => {
        const msg = websocket.ClientboundMessage.deserialize(ev.data);
        switch (msg.payload) {
          case 'challenge': {
            console.log('[WS] <-', msg.toObject());
            send({
              challenge_response: new websocket.ChallengeResponse({
                handle: identity.handle,
                signature: xeddsa_sign(identity.priv, msg.challenge.nonce, randomBytes(64))
              })
            }).then(error => {
              setStatus(error ? err(`server rejected authentication: ${websocket.Ack.Error[error]}`) : null);
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

  const contacts = useLiveQuery(async () => {
    const messages = await db.messages.toArray();
    const peers = Array.from(new Set(messages.map(msg => msg.peer)));
    return Promise.all(
      peers.map(async handle => {
        const lastMsg = (await db.messages.where({ peer: handle }).last()) ?? null;
        if (!lastMsg) return { handle, lastMessage: null };
        return {
          handle,
          lastMessage: {
            sender: lastMsg.sender,
            text: lastMsg.text ?? ''
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

  const messages = useLiveQuery(async () => {
    if (!selectedContact) return [];
    const messages = await db.messages.where({ peer: selectedContact }).toArray();
    return messages.sort((a, b) => a.timestamp - b.timestamp);
  }, [selectedContact]);

  const sendNewMessage = useCallback(
    async (text: string, replyTo?: Message['id']) => {
      if (!selectedContact || !text.trim()) return false;

      let id = (await db.messages.where({ peer: selectedContact }).last())?.id;
      if (id !== undefined) id += 1;
      else id = 0;
      console.log({ id });
      const timestamp = Date.now();

      const payload = new secret.Payload({
        msg_new: new secret.Message({
          id,
          text: text.trim(),
          attachments: [],
          timestamp,
          reply_to: replyTo
        })
      });

      await db.messages.add({
        id,
        peer: selectedContact,
        sender: identity.handle,
        text,
        reply_to: replyTo ?? null,
        timestamp,
        last_edited_at: null,
        status: 'pending'
      });

      const err = await sendMessage(selectedContact, payload, { keyBundleProvider: getKeyBundle }).then(send);
      if (err) {
        console.error(err); // TODO: handle error
        return false;
      }

      await db.messages.where({ peer: selectedContact, sender: identity.handle, id }).modify(msg => {
        msg.status = 'sent';
      });

      return true;
    },
    [selectedContact, identity, send, getKeyBundle]
  );

  const editMessage = useCallback(
    async (msg: Message, newText: string) => {
      if (!selectedContact || !newText.trim()) return false;

      const timestamp = Date.now();

      const conditions = { peer: selectedContact, sender: identity.handle, id: msg.id };
      await db.messages.where(conditions).modify(msg => {
        msg.text = newText.trim();
        msg.last_edited_at = timestamp;
        msg.status = 'pending';
      });

      const payload = new secret.Payload({
        msg_edit: new secret.MsgEdit({
          id: msg.id,
          timestamp,
          attachment_ids: [],
          text: newText
        })
      });

      const err = await sendMessage(selectedContact, payload, { keyBundleProvider: getKeyBundle }).then(send);
      if (err) {
        console.error(err); // TODO: handle error
        return false;
      }

      await db.messages.where(conditions).modify(msg => {
        msg.status = 'sent';
      });

      return true;
    },
    [selectedContact, send, getKeyBundle]
  );

  // Delete a message
  const deleteMessage = useCallback(
    async (msg: Message) => {
      if (!selectedContact) return false;

      const payload = new secret.Payload({
        msg_delete: new secret.MsgDelete({
          id: msg.id
        })
      });

      const err = await sendMessage(selectedContact, payload, { keyBundleProvider: getKeyBundle }).then(send);
      if (err) {
        console.error(err); // TODO: handle error
        return false;
      }

      await db.messages.where({ peer: selectedContact, sender: identity.handle, id: msg.id }).delete();

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
    sendMessage: sendNewMessage,
    editMessage,
    deleteMessage
  };
}

import NewConversationModal from 'components/new-conversation-modal';
import { useLiveQuery } from 'dexie-react-hooks';
import { messages as messages_proto } from 'generated/messages';
import { websocket } from 'generated/websocket';
import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { useLocation } from 'wouter';
import { API_BASE_URL, fetchKeyBundle } from '~/lib/api';
import { randomBytes, xeddsa_sign } from '~/lib/crypto';
import { db } from '~/lib/db';
import { decryptLocal, encryptLocal, recvMessage, sendMessage } from '~/lib/protocol';
import { cn, eq } from '~/lib/utils';

export function HomeView() {
  const [, navigate] = useLocation();

  const wsRef = useRef<(WebSocket & { msgId: number }) | null>(null);

  const [loadingStage, setLoadingStage] = useState<'identity' | 'ws.connect' | 'ws.auth' | null>('identity');
  const [identity, setIdentity] = useState<{ handle: string; sigKey: Uint8Array }>(null!);
  const [newConvoOpen, setNewConvoOpen] = useState(false);
  const [selectedContact, setSelectedContact] = useState<string | null>(null);

  const contacts = useLiveQuery(async () => {
    const messages = await db.messages.toArray();
    const peers = Array.from(new Set(messages.map(msg => msg.peer)));
    return await Promise.all(
      peers.map(async handle => {
        const lastMessage = (await db.messages.where({ peer: handle }).last()) ?? null;
        if (!lastMessage) return { handle, lastMessage };
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

  const messages = useLiveQuery(async () => {
    if (!selectedContact) return [];
    const messages = await db.messages.where({ peer: selectedContact }).toArray();
    const decrypted = await Promise.all(
      messages.map(async ({ id, sender, ciphertext, nonce }) => {
        const plaintext = await decryptLocal(ciphertext, nonce);
        const payload = messages_proto.MessagePayload.deserialize(plaintext);
        return {
          id,
          sender,
          text: payload.text ?? ''
        };
      })
    );
    return decrypted.sort((a, b) => a.id - b.id);
  }, [selectedContact]);

  const statusTranslation = useMemo(
    () =>
      ({
        identity: 'Loading identity...',
        'ws.connect': 'Connecting to WebSocket...',
        'ws.auth': 'Authenticating...'
      }) satisfies Record<NonNullable<typeof loadingStage>, string>,
    []
  );

  async function send(
    ws: WebSocket & { msgId: number },
    msg: Omit<Exclude<ConstructorParameters<typeof websocket.ServerboundMessage>[0] & {}, any[]>, 'id'>
  ): Promise<websocket.Ack.Error | null> {
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
  }

  async function onForwardPb(msg: websocket.Forward) {
    const payload = await recvMessage(msg); // todo: handle exception
    const { ciphertext, nonce } = await encryptLocal(payload.serialize());
    await db.messages.add({
      peer: msg.handle,
      sender: msg.handle,
      ciphertext,
      nonce
    });
    // todo: notification if recipient is not currently open or the message is out of scroll
  }

  const handleStartConversation: Parameters<typeof NewConversationModal>[0]['onStart'] = handle => {
    setSelectedContact(handle);
    setNewConvoOpen(false);
  };

  async function handleSend(e: FormEvent) {
    e.preventDefault();
    const form = e.target as HTMLFormElement;
    const input = form.querySelector<HTMLInputElement>('input[type="text"]');
    const content = input?.value;
    if (!input || !content?.trim() || !selectedContact) return;

    input.value = '';

    const payload = new messages_proto.MessagePayload({
      text: content,
      attachments: []
    });

    const forward = await sendMessage(selectedContact, payload, async handle => {
      const keyBundle = await fetchKeyBundle(handle);
      if (keyBundle.isErr()) return keyBundle;
      const lastKnownIdKey = await db.identity_keys.get(handle);
      if (!lastKnownIdKey) return keyBundle;
      if (eq(keyBundle.value.id_key, lastKnownIdKey.pub)) return keyBundle;
      throw new Error('KEY_MISMATCH');
    }); // todo: handle exception
    const err = await send(wsRef.current!, { forward });

    if (err) {
      input.value = content;
      input.focus();
      // todo: show error to user, include fingerprint of both keys in case of key mismatch
      console.error(err);
      return;
    }

    const { ciphertext, nonce } = await encryptLocal(payload.serialize());
    await db.messages.add({
      peer: selectedContact,
      sender: identity.handle,
      ciphertext,
      nonce
    });
  }

  useEffect(() => {
    (async () => {
      const identity = await db.identity.limit(1).first();
      if (!identity) {
        return navigate('/register');
      }
      setIdentity({ handle: identity.handle, sigKey: identity.pub });

      setLoadingStage('ws.connect');

      const ws = new WebSocket(`${API_BASE_URL}/api/ws`) as NonNullable<typeof wsRef.current>;
      ws.msgId = 0;
      ws.binaryType = 'arraybuffer';
      wsRef.current = ws;

      ws.onopen = () => {
        setLoadingStage('ws.auth');
      };

      ws.onmessage = ev => {
        const msg = websocket.ClientboundMessage.deserialize(ev.data);
        console.log('[WS] clientbound', msg.toObject());
        switch (msg.payload) {
          case 'challenge': {
            send(ws, {
              challenge_response: new websocket.ChallengeResponse({
                handle: identity.handle,
                signature: xeddsa_sign(identity.priv, msg.challenge.nonce, randomBytes(64))
              })
            }).then(err => {
              if (err) {
                // TODO: handle error
                setLoadingStage(null);
                return;
              }
              setLoadingStage(null);
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
  }, []);

  if (loadingStage) {
    return (
      <main className="min-h-screen bg-[#F2F6FC] text-[#0C0C0C] dark:bg-[#0C0C0C] dark:text-[#F2F6FC]">
        <div className="flex min-h-screen items-center justify-center">
          <p className="text-sm">{statusTranslation[loadingStage]}</p>
        </div>
      </main>
    );
  }

  return (
    <>
      <NewConversationModal
        isOpen={newConvoOpen}
        onClose={() => setNewConvoOpen(false)}
        onStart={handleStartConversation}
      />
      <main className="flex h-screen bg-[#F2F6FC] text-[#0C0C0C] dark:bg-[#0C0C0C] dark:text-[#F2F6FC]">
        <aside
          className={`flex shrink-0 flex-col border-r border-[#0C0C0C] transition-all duration-200 dark:border-[#F2F6FC] ${
            true ? 'w-72' : 'w-0 overflow-hidden border-r-0'
          }`}
        >
          <div className="flex shrink-0 items-center justify-between border-b border-[#0C0C0C] px-4 py-3 dark:border-[#F2F6FC]">
            <span className="text-sm font-semibold">Contacts</span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setNewConvoOpen(true)}
                className="flex h-6 w-6 items-center justify-center border border-[#0C0C0C] text-sm hover:bg-[#0C0C0C] hover:text-[#F2F6FC] dark:border-[#F2F6FC] dark:hover:bg-[#F2F6FC] dark:hover:text-[#0C0C0C]"
                aria-label="New conversation"
                title="New conversation"
              >
                +
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto">
            {[
              ...(contacts ?? []),
              ...(selectedContact && !contacts?.some(c => c.handle === selectedContact)
                ? [{ handle: selectedContact, lastMessage: null }]
                : [])
            ].map(contact => (
              <button
                key={contact.handle}
                onClick={() => setSelectedContact(contact.handle)}
                className={cn(
                  'flex w-full items-center gap-3 border-b border-[#0C0C0C] px-4 py-3 text-left transition-colors dark:border-[#F2F6FC]',
                  contact.handle === selectedContact
                    ? 'bg-[#0C0C0C] text-[#F2F6FC] dark:bg-[#F2F6FC] dark:text-[#0C0C0C]'
                    : 'hover:bg-[#0C0C0C]/5 dark:hover:bg-[#F2F6FC]/5'
                )}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium">{contact.handle}</span>
                    {/* {contact.lastMessageTime && (
                      <span
                        className={`shrink-0 text-[10px] ${
                          selectedContact === contact.handle
                            ? 'text-zinc-400 dark:text-zinc-500'
                            : 'text-zinc-500 dark:text-zinc-400'
                        }`}
                      >
                        {formatRelativeTime(contact.lastMessageTime)}
                      </span>
                    )} */}
                  </div>
                  {contact.lastMessage && (
                    <p
                      className={`truncate text-xs ${
                        selectedContact === contact.handle
                          ? 'text-zinc-400 dark:text-zinc-500'
                          : 'text-zinc-500 dark:text-zinc-400'
                      }`}
                    >
                      {contact.lastMessage.sender === identity.handle ? 'You: ' : `${contact.lastMessage.sender}: `}
                      {contact.lastMessage.text}
                    </p>
                  )}
                </div>
              </button>
            ))}
          </div>

          {/* <div className="shrink-0 border-t border-[#0C0C0C] px-4 py-3 dark:border-[#F2F6FC]">
            <div className="flex items-center gap-3">
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium">{identity.handle}</div>
              </div>
            </div>
          </div> */}
        </aside>

        {/* Main chat area */}
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex shrink-0 items-center justify-between border-b border-[#0C0C0C] px-4 py-3 dark:border-[#F2F6FC]">
            <div className="flex items-center gap-3">
              {/* <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="flex h-8 w-8 items-center justify-center border border-[#0C0C0C] text-sm hover:bg-[#0C0C0C] hover:text-[#F2F6FC] dark:border-[#F2F6FC] dark:hover:bg-[#F2F6FC] dark:hover:text-[#0C0C0C]"
                aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
              >
                {true ? '✕' : '☰'}
              </button> */}
              <div className="text-sm font-semibold">{selectedContact}</div>
            </div>
          </header>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-4 py-4">
            <div className="mx-auto max-w-2xl space-y-3">
              {messages?.map(msg => (
                <div
                  key={msg.id}
                  className={`flex ${msg.sender === identity.handle ? 'justify-end' : 'justify-start'}`}
                >
                  <div
                    className={`max-w-[75%] border px-3 py-2 ${
                      msg.sender === identity.handle
                        ? 'border-[#0C0C0C] bg-[#0C0C0C] text-[#F2F6FC] dark:border-[#F2F6FC] dark:bg-[#F2F6FC] dark:text-[#0C0C0C]'
                        : 'border-[#0C0C0C] bg-transparent dark:border-[#F2F6FC]'
                    }`}
                  >
                    <div className="text-sm">{msg.text}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Input area */}
          <div className="shrink-0 border-t border-[#0C0C0C] px-4 py-3 dark:border-[#F2F6FC]">
            <div className="mx-auto max-w-2xl space-y-2">
              {/* Input form */}
              <form onSubmit={handleSend} className="flex gap-2">
                <input
                  type="text"
                  placeholder="Type a message…"
                  className="flex-1 border border-[#0C0C0C] bg-transparent px-3 py-2 text-sm text-[#0C0C0C] placeholder:text-zinc-500 focus:ring-2 focus:ring-[#0C0C0C] focus:ring-offset-2 focus:ring-offset-[#F2F6FC] focus:outline-none dark:border-[#F2F6FC] dark:text-[#F2F6FC] dark:placeholder:text-zinc-400 dark:focus:ring-[#F2F6FC] dark:focus:ring-offset-[#0C0C0C]"
                />
                <button
                  type="submit"
                  disabled={!selectedContact}
                  className="border border-[#0C0C0C] bg-[#0C0C0C] px-4 py-2 text-sm font-medium text-[#F2F6FC] hover:bg-transparent hover:text-[#0C0C0C] focus:ring-2 focus:ring-[#0C0C0C] focus:ring-offset-2 focus:ring-offset-[#F2F6FC] focus:outline-none disabled:cursor-not-allowed disabled:opacity-60 dark:border-[#F2F6FC] dark:bg-[#F2F6FC] dark:text-[#0C0C0C] dark:hover:bg-transparent dark:hover:text-[#F2F6FC] dark:focus:ring-[#F2F6FC] dark:focus:ring-offset-[#0C0C0C]"
                >
                  Send
                </button>
              </form>
            </div>
          </div>
        </div>
      </main>
    </>
  );
}

export default HomeView;

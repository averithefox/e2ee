import { useLiveQuery } from 'dexie-react-hooks';
import type { messages } from 'generated/messages';
import { websocket } from 'generated/websocket';
import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { useLocation } from 'wouter';
import { API_BASE_URL, fetchKeyBundle } from '~/lib/api';
import { randomBytes, xeddsa_sign } from '~/lib/crypto';
import { db } from '~/lib/db';
import { decryptLocal, encryptLocal, recvMessage, sendMessage, verifyKeyBundle } from '~/lib/protocol';
import { cn, eq } from '~/lib/utils';

function formatFingerprint(key: Uint8Array): string {
  const hex = Array.from(key)
    .map(b => b.toString(16).padStart(2, '0').toUpperCase())
    .join('');
  // Group into 4-char chunks separated by spaces
  return hex.match(/.{1,4}/g)?.join(' ') ?? hex;
}

function NewConversationModal({
  isOpen,
  onClose,
  onStart
}: {
  isOpen: boolean;
  onClose: () => void;
  onStart: (handle: string, keyBundle: messages.PQXDHKeyBundle) => void;
}) {
  const [recipientHandle, setRecipientHandle] = useState('');
  const [keyBundle, setKeyBundle] = useState<messages.PQXDHKeyBundle | null>(null);
  const [storedIdKey, setStoredIdKey] = useState<Uint8Array | null>(null);
  const [lookupStatus, setLookupStatus] = useState<'idle' | 'loading' | 'found' | 'not_found' | 'invalid_signature'>(
    'idle'
  );
  const inputRef = useRef<HTMLInputElement>(null);

  function resetKeyState() {
    setKeyBundle(null);
    setStoredIdKey(null);
  }

  useEffect(() => {
    if (isOpen) {
      setRecipientHandle('');
      resetKeyState();
      setLookupStatus('idle');
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isOpen, onClose]);

  useEffect(() => {
    if (!isOpen) return;

    const handle = recipientHandle.trim();
    if (!handle) {
      resetKeyState();
      setLookupStatus('idle');
      return;
    }

    const controller = new AbortController();
    setLookupStatus('loading');

    (async () => {
      try {
        const res = await fetchKeyBundle(handle, { signal: controller.signal });

        if (res.isErr()) {
          resetKeyState();
          setLookupStatus(res.error === 404 ? 'not_found' : 'idle');
          return;
        }

        const storedIdKey = await db.identity_keys.get(handle);

        console.log(storedIdKey, res.value.toObject());
        if (!verifyKeyBundle(res.value)) {
          resetKeyState();
          setLookupStatus('invalid_signature');
          return;
        }

        setStoredIdKey(storedIdKey?.pub ?? null);

        setKeyBundle(res.value);
        setLookupStatus('found');
      } catch (err) {
        if ((err as Error).name !== 'AbortError') {
          resetKeyState();
          setLookupStatus('idle');
        }
      }
    })();

    return () => controller.abort();
  }, [isOpen, recipientHandle]);

  if (!isOpen) return null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const h = recipientHandle.trim();
    if (h && keyBundle && lookupStatus === 'found') {
      await db.identity_keys.put({ for: h, pub: keyBundle.id_key }, h);
      onStart(h, keyBundle);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-[#0C0C0C]/50 dark:bg-[#F2F6FC]/10" onClick={onClose} />
      <div className="relative w-full max-w-sm border border-[#0C0C0C] bg-[#F2F6FC] p-6 text-[#0C0C0C] dark:border-[#F2F6FC] dark:bg-[#0C0C0C] dark:text-[#F2F6FC]">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-zinc-500 hover:text-[#0C0C0C] dark:text-zinc-400 dark:hover:text-[#F2F6FC]"
          aria-label="Close"
        >
          ✕
        </button>
        <h2 className="text-lg font-semibold">New Conversation</h2>
        <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Enter recipient handle</p>
        <form onSubmit={handleSubmit} className="mt-4 space-y-3">
          <input
            ref={inputRef}
            type="text"
            value={recipientHandle}
            onChange={e => setRecipientHandle(e.target.value)}
            placeholder="Handle"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            className="w-full border border-[#0C0C0C] bg-transparent px-3 py-2 text-sm text-[#0C0C0C] placeholder:text-zinc-500 focus:ring-2 focus:ring-[#0C0C0C] focus:ring-offset-2 focus:ring-offset-[#F2F6FC] focus:outline-none dark:border-[#F2F6FC] dark:text-[#F2F6FC] dark:placeholder:text-zinc-400 dark:focus:ring-[#F2F6FC] dark:focus:ring-offset-[#0C0C0C]"
            autoFocus
          />
          <div>
            {
              {
                loading: <div className="text-xs text-zinc-500 dark:text-zinc-400">Looking up identity…</div>,
                not_found: <div className="text-xs text-red-600 dark:text-red-400">User not found</div>,
                invalid_signature: <div className="text-xs text-red-600 dark:text-red-400">Invalid signature</div>,
                idle: null,
                found: keyBundle && (
                  <div className="space-y-1">
                    <div className="text-[10px] font-medium tracking-wide text-zinc-500 uppercase dark:text-zinc-400">
                      Identity Key Fingerprint
                    </div>
                    <p
                      className={cn(
                        'font-mono text-xs leading-relaxed break-all',
                        !storedIdKey || eq(keyBundle.id_key, storedIdKey)
                          ? 'text-indigo-600 dark:text-indigo-400'
                          : 'text-red-600 dark:text-red-400'
                      )}
                    >
                      {formatFingerprint(keyBundle.id_key)}
                    </p>
                  </div>
                )
              }[lookupStatus]
            }
          </div>

          {keyBundle && storedIdKey && !eq(keyBundle.id_key, storedIdKey) && (
            <div className="w-full space-y-2 bg-red-600 p-2 text-sm text-white dark:bg-red-400">
              <p>
                The identity key provided by the server does not match {recipientHandle}'
                {recipientHandle.endsWith('s') ? '' : 's'} last known identity key.
              </p>
              <p className="font-mono text-xs leading-relaxed break-all">{formatFingerprint(storedIdKey)}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={!recipientHandle.trim() || lookupStatus !== 'found'}
            className="w-full border border-[#0C0C0C] bg-[#0C0C0C] px-3 py-2 text-sm font-medium text-[#F2F6FC] not-disabled:hover:bg-transparent not-disabled:hover:text-[#0C0C0C] focus:ring-2 focus:ring-[#0C0C0C] focus:ring-offset-2 focus:ring-offset-[#F2F6FC] focus:outline-none disabled:cursor-not-allowed disabled:opacity-60 dark:border-[#F2F6FC] dark:bg-[#F2F6FC] dark:text-[#0C0C0C] not-disabled:dark:hover:bg-transparent not-disabled:dark:hover:text-[#F2F6FC] dark:focus:ring-[#F2F6FC] dark:focus:ring-offset-[#0C0C0C]"
          >
            Start
          </button>
        </form>
      </div>
    </div>
  );
}

function getWsUrl(): string {
  const base = API_BASE_URL || window.location.origin;
  const url = new URL(base);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.pathname = '/api/ws';
  return url.toString();
}

export function HomeView() {
  const [, navigate] = useLocation();

  const wsRef = useRef<(WebSocket & { msgId: number }) | null>(null);

  const [loadingStage, setLoadingStage] = useState<'identity' | 'ws.connect' | 'ws.auth' | null>('identity');
  const [identity, setIdentity] = useState<{ handle: string; sigKey: Uint8Array }>(null!);
  const [newConvoOpen, setNewConvoOpen] = useState(false);
  const [selectedContact, setSelectedContact] = useState<string | null>(null);

  const contacts = useLiveQuery(async () => {
    const messages = await db.messages.toArray();
    return new Set(messages.map(msg => msg.peer));
  });

  const messages = useLiveQuery(async () => {
    if (!selectedContact) return [];
    const messages = await db.messages.where({ peer: selectedContact }).toArray();
    const decrypted = await Promise.all(
      messages.map(async ({ id, sender, ciphertext, nonce }) => ({
        id,
        sender,
        content: await decryptLocal(ciphertext, nonce)
      }))
    );
    return decrypted.sort((a, b) => a.id - b.id);
  }, [selectedContact]);

  const identityTranslation = useMemo(
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
    const content = await recvMessage(msg); // todo: handle exception
    const { ciphertext, nonce } = await encryptLocal(content);
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

    const forward = await sendMessage(selectedContact, content, async handle => {
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

    const { ciphertext, nonce } = await encryptLocal(content);
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

      const ws = new WebSocket(getWsUrl()) as NonNullable<typeof wsRef.current>;
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
          <p className="text-sm">{identityTranslation[loadingStage]}</p>
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
            {Array.from(new Set([...(contacts ?? []), ...(selectedContact ? [selectedContact] : [])])).map(contact => (
              <button
                key={contact}
                onClick={() => setSelectedContact(contact)}
                className={cn(
                  'flex w-full items-center gap-3 border-b border-[#0C0C0C] px-4 py-3 text-left transition-colors dark:border-[#F2F6FC]',
                  selectedContact === contact
                    ? 'bg-[#0C0C0C] text-[#F2F6FC] dark:bg-[#F2F6FC] dark:text-[#0C0C0C]'
                    : 'hover:bg-[#0C0C0C]/5 dark:hover:bg-[#F2F6FC]/5'
                )}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium">{contact}</span>
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
                  {/* {contact.lastMessage && (
                    <p
                      className={`truncate text-xs ${
                        selectedContact === contact.handle
                          ? 'text-zinc-400 dark:text-zinc-500'
                          : 'text-zinc-500 dark:text-zinc-400'
                      }`}
                    >
                      {contact.lastMessage}
                    </p>
                  )} */}
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
                    <div className="text-sm">{msg.content}</div>
                    {/* <div
                      className={`mt-1 text-right text-[10px] ${
                        msg.sender === identity.handle ? 'text-zinc-400 dark:text-zinc-500' : 'text-zinc-500 dark:text-zinc-400'
                      }`}
                    >
                      {formatTime(msg.timestamp)}
                    </div> */}
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
                  // value={inputValue}
                  // onChange={e => setInputValue(e.target.value)}
                  placeholder="Type a message…"
                  className="flex-1 border border-[#0C0C0C] bg-transparent px-3 py-2 text-sm text-[#0C0C0C] placeholder:text-zinc-500 focus:ring-2 focus:ring-[#0C0C0C] focus:ring-offset-2 focus:ring-offset-[#F2F6FC] focus:outline-none dark:border-[#F2F6FC] dark:text-[#F2F6FC] dark:placeholder:text-zinc-400 dark:focus:ring-[#F2F6FC] dark:focus:ring-offset-[#0C0C0C]"
                />
                <button
                  type="submit"
                  // disabled={!inputValue.trim()}
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

import { useLiveQuery } from 'dexie-react-hooks';
import { messages as messages_proto } from 'generated/messages';
import { websocket } from 'generated/websocket';
import { CornerDownLeft, Loader2, OctagonX, Plus, Reply, SidebarClose, SidebarOpen, X } from 'lucide-react';
import { err, ok, type Result } from 'neverthrow';
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { useLocation } from 'wouter';
import NewConversationModal from '~/components/new-conversation-modal';
import { Button } from '~/components/ui/button';
import { Input } from '~/components/ui/input';
import { API_BASE_URL, fetchKeyBundle } from '~/lib/api';
import { randomBytes, xeddsa_sign } from '~/lib/crypto';
import { db } from '~/lib/db';
import { decryptLocal, encryptLocal, recvMessage, sendMessage } from '~/lib/protocol';
import { cn, eq } from '~/lib/utils';

type MessageData = {
  id: Uint8Array;
  sender: string;
  text: string | null;
  timestamp: number;
  reply_to: Uint8Array | null;
};

function formatTime(timestamp: number): string {
  const date = new Date(timestamp);
  const now = new Date();
  const isToday = date.toDateString() === now.toDateString();
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  const isYesterday = date.toDateString() === yesterday.toDateString();

  const time = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  if (isToday) return time;
  if (isYesterday) return `Yesterday ${time}`;
  return `${date.toLocaleDateString([], { month: 'short', day: 'numeric' })} ${time}`;
}

export function HomeView() {
  const [, navigate] = useLocation();

  const wsRef = useRef<(WebSocket & { msgId: number; connectAttempts: number }) | null>(null);
  const inputRef = useRef<HTMLInputElement>(null!);

  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [status, setStatus] = useState<Result<string, string> | null>();
  const [identity, setIdentity] = useState<{ handle: string; sigKey: Uint8Array }>(null!);
  const [newConvoOpen, setNewConvoOpen] = useState(false);
  const [selectedContact, setSelectedContact] = useState<string | null>(null);
  const [replyingTo, setReplyingTo] = useState<MessageData | null>(null);
  const [highlightedMsgId, setHighlightedMsgId] = useState<Uint8Array | null>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);

  const contacts = useLiveQuery(async () => {
    const messages = await db.messages.toArray();
    const peers = Array.from(new Set(messages.map(msg => msg.peer)));
    return Promise.all(
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

  const messages = useLiveQuery(async (): Promise<MessageData[]> => {
    if (!selectedContact) return [];
    const messages = await db.messages.where({ peer: selectedContact }).toArray();
    const decrypted = await Promise.all(
      messages.map(async ({ sender, ciphertext, nonce }): Promise<MessageData> => {
        const plaintext = await decryptLocal(ciphertext, nonce);
        const payload = messages_proto.MessagePayload.deserialize(plaintext);
        return {
          id: payload.uuid,
          sender,
          text: payload.has_text ? payload.text : null,
          timestamp: payload.timestamp,
          reply_to: payload.has_reply_to ? payload.reply_to : null
        };
      })
    );
    return decrypted.sort((a, b) => a.timestamp - b.timestamp);
  }, [selectedContact]);

  const scrollToMessage = useCallback((targetId: Uint8Array) => {
    const container = messagesContainerRef.current;
    if (!container) return;

    const idStr = Array.from(targetId).join(',');
    const el = container.querySelector(`[data-msg-id="${idStr}"]`);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      setHighlightedMsgId(targetId);
      setTimeout(() => setHighlightedMsgId(null), 1500);
    }
  }, []);

  const findMessageById = useCallback(
    (id: Uint8Array): MessageData | undefined => {
      return messages?.find(m => eq(m.id, id));
    },
    [messages]
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
    setReplyingTo(null);
    setNewConvoOpen(false);
  };

  const handleSelectContact = (handle: string) => {
    setSelectedContact(handle);
    setReplyingTo(null);
  };

  async function handleSend(e: FormEvent) {
    e.preventDefault();
    const form = e.target as HTMLFormElement;
    const input = form.querySelector<HTMLInputElement>('input[type="text"]');
    const content = input?.value;
    if (!input || !content?.trim() || !selectedContact) return;

    input.value = '';
    const currentReplyTo = replyingTo;
    setReplyingTo(null);

    const payload = new messages_proto.MessagePayload({
      uuid: randomBytes(16),
      text: content,
      attachments: [],
      timestamp: Date.now(),
      ...(currentReplyTo && { reply_to: currentReplyTo.id })
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
            send(ws, {
              challenge_response: new websocket.ChallengeResponse({
                handle: identity.handle,
                signature: xeddsa_sign(identity.priv, msg.challenge.nonce, randomBytes(64))
              })
            }).then(error => {
              if (error) {
                setStatus(err(`server rejected authentication: ${websocket.Ack.Error[error]}`));
                return;
              }
              setStatus(null);
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

  const contactsList = useMemo(() => {
    const list = [...(contacts ?? [])];
    if (selectedContact && !contacts?.some(c => c.handle === selectedContact)) {
      list.push({ handle: selectedContact, lastMessage: null });
    }
    return list;
  }, [contacts, selectedContact]);

  if (status !== null) {
    if (!status) return null;
    return (
      <main className="bg-background text-foreground flex min-h-screen items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          {status.isErr() ? (
            <OctagonX className="text-destructive size-6" />
          ) : (
            <Loader2 className="size-6 animate-spin" />
          )}
          <p className="text-muted-foreground text-sm capitalize">{status.isErr() ? status.error : status.value}</p>
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
      <main className="bg-background text-foreground flex h-screen overflow-hidden">
        <aside
          className={cn(
            'bg-card border-border flex shrink-0 flex-col border-r transition-all duration-200',
            sidebarOpen ? 'w-72' : 'w-0 overflow-hidden border-r-0'
          )}
        >
          <div className="border-border flex h-14 shrink-0 items-center justify-between border-b px-4">
            <span className="text-sm font-semibold">Contacts</span>
            <Button
              variant="outline"
              size="icon-sm"
              onClick={() => setNewConvoOpen(true)}
              aria-label="New conversation"
              title="New conversation"
            >
              <Plus className="size-4" />
            </Button>
          </div>

          <div className="flex-1 overflow-y-auto">
            {contactsList.length === 0 ? (
              <div className="text-muted-foreground flex h-full items-center justify-center p-4 text-center text-sm">
                No conversations yet.
                <br />
                Start one with the + button.
              </div>
            ) : (
              contactsList.map(contact => (
                <button
                  key={contact.handle}
                  onClick={() => handleSelectContact(contact.handle)}
                  className={cn(
                    'border-border flex w-full items-center gap-3 border-b px-4 py-3 text-left transition-colors',
                    contact.handle === selectedContact ? 'bg-accent text-accent-foreground' : 'hover:bg-muted/50'
                  )}
                >
                  <div className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{contact.handle}</span>
                    <p className="text-muted-foreground truncate text-xs">{contact.lastMessage?.text}</p>
                  </div>
                </button>
              ))
            )}
          </div>

          <div className="border-border flex shrink-0 items-center gap-3 border-t px-4 py-3">
            <span className="text-muted-foreground truncate text-sm">{identity?.handle}</span>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="border-border flex h-14 shrink-0 items-center gap-3 border-b px-4">
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={() => setSidebarOpen(!sidebarOpen)}
              aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
            >
              {sidebarOpen ? <SidebarClose className="size-4" /> : <SidebarOpen className="size-4" />}
            </Button>
            {selectedContact ? (
              <div className="flex items-center gap-3">
                <span className="text-sm font-semibold">{selectedContact}</span>
              </div>
            ) : (
              <span className="text-muted-foreground text-sm">Select a conversation</span>
            )}
          </header>

          <div ref={messagesContainerRef} className="flex-1 overflow-y-auto p-4">
            {!selectedContact ? (
              <div className="text-muted-foreground flex h-full items-center justify-center text-sm">
                Select a contact to start chatting
              </div>
            ) : messages?.length === 0 ? (
              <div className="text-muted-foreground flex h-full items-center justify-center text-sm">
                No messages yet. Say hello!
              </div>
            ) : (
              <div className="mx-auto max-w-2xl space-y-3">
                {messages?.map(msg => {
                  const isOwn = msg.sender === identity.handle;
                  const idStr = Array.from(msg.id).join(',');
                  const isHighlighted = highlightedMsgId && eq(highlightedMsgId, msg.id);
                  const repliedMessage = msg.reply_to ? findMessageById(msg.reply_to) : null;

                  return (
                    <div
                      key={idStr}
                      data-msg-id={idStr}
                      className={cn('group flex items-end gap-2', isOwn ? 'flex-row-reverse' : 'flex-row')}
                    >
                      <div
                        className={cn(
                          'max-w-[75%] transition-all duration-300',
                          isHighlighted && 'ring-ring ring-offset-background scale-[1.02] ring-2 ring-offset-2'
                        )}
                      >
                        {msg.reply_to && (
                          <button
                            type="button"
                            onClick={() => scrollToMessage(msg.reply_to!)}
                            className={cn(
                              'mb-1 flex w-full items-center gap-1.5 rounded-t-lg border-l-2 px-2.5 py-1.5 text-left text-xs transition-colors',
                              isOwn
                                ? 'border-primary-foreground/40 bg-primary/80 text-primary-foreground/70 hover:bg-primary/90'
                                : 'border-muted-foreground/40 bg-muted/80 text-muted-foreground hover:bg-muted/90'
                            )}
                          >
                            <CornerDownLeft className="size-3 shrink-0" />
                            <span className="truncate">
                              {repliedMessage
                                ? repliedMessage.text?.slice(0, 50) +
                                  (repliedMessage.text && repliedMessage.text.length > 50 ? '…' : '')
                                : 'Original message'}
                            </span>
                          </button>
                        )}

                        <div
                          className={cn(
                            'rounded-lg px-3 py-2 text-sm',
                            msg.reply_to && 'rounded-t-none',
                            isOwn ? 'bg-primary text-primary-foreground' : 'bg-muted text-foreground'
                          )}
                        >
                          <p>{msg.text}</p>
                          <p
                            className={cn(
                              'mt-1 text-[10px]',
                              isOwn ? 'text-primary-foreground/60' : 'text-muted-foreground'
                            )}
                          >
                            {formatTime(msg.timestamp)}
                          </p>
                        </div>
                      </div>

                      <Button
                        variant="ghost"
                        size="icon-sm"
                        onClick={() => {
                          setReplyingTo(msg);
                          inputRef.current.focus();
                        }}
                        className="shrink-0 opacity-0 transition-opacity group-hover:opacity-100"
                        aria-label="Reply to message"
                      >
                        <Reply className="size-3.5" />
                      </Button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="shrink-0 p-2">
            {replyingTo && (
              <div className="bg-muted/50 border-primary mb-2 flex items-center gap-2 rounded-lg border-l-2 px-3 py-2">
                <Reply className="text-muted-foreground size-4 shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-muted-foreground text-xs font-medium">
                    Replying to {replyingTo.sender === identity.handle ? 'yourself' : replyingTo.sender}
                  </p>
                  <p className="truncate text-sm">{replyingTo.text}</p>
                </div>
                <Button variant="ghost" size="icon-sm" onClick={() => setReplyingTo(null)} aria-label="Cancel reply">
                  <X className="size-4" />
                </Button>
              </div>
            )}
            <form onSubmit={handleSend} className="relative">
              <Input
                ref={inputRef}
                type="text"
                placeholder={selectedContact ? `Message ${selectedContact}` : 'Select a contact first'}
                disabled={!selectedContact}
                className="bg-background dark:bg-background h-11 pr-11"
              />
            </form>
          </div>
        </div>
      </main>
    </>
  );
}

export default HomeView;

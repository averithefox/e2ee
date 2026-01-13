import { useLiveQuery } from 'dexie-react-hooks';
import { messages as messages_proto } from 'generated/messages';
import { websocket } from 'generated/websocket';
import { Loader2, OctagonX, Plus, Send, SidebarClose, SidebarOpen } from 'lucide-react';
import { err, ok, type Result } from 'neverthrow';
import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { useLocation } from 'wouter';
import NewConversationModal from '~/components/new-conversation-modal';
import { Button } from '~/components/ui/button';
import { Input } from '~/components/ui/input';
import { API_BASE_URL, fetchKeyBundle } from '~/lib/api';
import { randomBytes, xeddsa_sign } from '~/lib/crypto';
import { db } from '~/lib/db';
import { decryptLocal, encryptLocal, recvMessage, sendMessage } from '~/lib/protocol';
import { cn, eq } from '~/lib/utils';

export function HomeView() {
  const [, navigate] = useLocation();

  const wsRef = useRef<(WebSocket & { msgId: number; connectAttempts: number }) | null>(null);

  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [status, setStatus] = useState<Result<string, string> | null>();
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
    return Promise.all(
      messages.map(async ({ id, sender, ciphertext, nonce }) => {
        const plaintext = await decryptLocal(ciphertext, nonce);
        const payload = messages_proto.MessagePayload.deserialize(plaintext);
        return {
          id: payload.uuid,
          sender,
          text: payload.text ?? ''
        };
      })
    );
  }, [selectedContact]);

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
      uuid: randomBytes(16),
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
      <main className="bg-background text-foreground flex h-screen">
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
                  onClick={() => setSelectedContact(contact.handle)}
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

          <div className="flex-1 overflow-y-auto p-4">
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
                {messages?.map(msg => (
                  <div
                    key={msg.id.toString()}
                    className={cn('flex', msg.sender === identity.handle ? 'justify-end' : 'justify-start')}
                  >
                    <div
                      className={cn(
                        'max-w-[75%] rounded-lg px-3 py-2 text-sm',
                        msg.sender === identity.handle
                          ? 'bg-primary text-primary-foreground'
                          : 'bg-muted text-foreground'
                      )}
                    >
                      {msg.text}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="shrink-0 p-2">
            <form onSubmit={handleSend} className="relative">
              <Input
                type="text"
                placeholder={selectedContact ? `Message ${selectedContact}` : 'Select a contact first'}
                disabled={!selectedContact}
                className="bg-background dark:bg-background h-11 pr-11"
              />
              <Button
                variant="outline"
                type="submit"
                size="icon-sm"
                disabled={!selectedContact}
                className="absolute top-1/2 right-1.5 -translate-y-1/2"
              >
                <Send className="size-4" />
                <span className="sr-only">Send</span>
              </Button>
            </form>
          </div>
        </div>
      </main>
    </>
  );
}

export default HomeView;

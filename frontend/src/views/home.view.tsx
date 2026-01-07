import { messages } from 'generated/messages';
import { websocket } from 'generated/websocket';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useLocation } from 'wouter';
import { randomBytes, xeddsaSign } from '~/lib/crypto';
import { loadHandle, loadKeys, type KeyBundle } from '~/lib/storage';
import { $fetch, API_BASE_URL } from '~/lib/utils';

type ConnectionStatus = 'connecting' | 'authenticating' | 'connected' | 'disconnected' | 'error';

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
  onStart,
  myHandle,
  myKeys
}: {
  isOpen: boolean;
  onClose: () => void;
  onStart: (handle: string) => void;
  myHandle: string | null;
  myKeys: KeyBundle | null;
}) {
  const [recipientHandle, setRecipientHandle] = useState('');
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [lookupStatus, setLookupStatus] = useState<'idle' | 'loading' | 'found' | 'not_found'>('idle');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setRecipientHandle('');
      setFingerprint(null);
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

  // Fetch key bundle on every keystroke
  useEffect(() => {
    if (!isOpen || !myHandle || !myKeys) return;

    const handle = recipientHandle.trim();
    if (!handle) {
      setFingerprint(null);
      setLookupStatus('idle');
      return;
    }

    const controller = new AbortController();
    setLookupStatus('loading');

    (async () => {
      try {
        const res = await $fetch(`${API_BASE_URL}/api/keys/${encodeURIComponent(handle)}/bundle`, {
          identity: { handle: myHandle, privateKey: myKeys.IK.privateKey },
          signal: controller.signal
        });

        if (!res.ok) {
          if (res.status === 404) {
            setFingerprint(null);
            setLookupStatus('not_found');
          } else {
            setFingerprint(null);
            setLookupStatus('idle');
          }
          return;
        }

        const data = new Uint8Array(await res.arrayBuffer());
        const bundle = messages.PQXDHKeyBundle.deserialize(data);
        setFingerprint(formatFingerprint(bundle.id_key));
        setLookupStatus('found');
      } catch (err) {
        if ((err as Error).name !== 'AbortError') {
          setFingerprint(null);
          setLookupStatus('idle');
        }
      }
    })();

    return () => controller.abort();
  }, [isOpen, recipientHandle, myHandle, myKeys]);

  if (!isOpen) return null;

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const h = recipientHandle.trim();
    if (h && lookupStatus === 'found') onStart(h);
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
            {lookupStatus === 'loading' && (
              <div className="text-xs text-zinc-500 dark:text-zinc-400">Looking up identity…</div>
            )}
            {lookupStatus === 'not_found' && (
              <div className="text-xs text-red-600 dark:text-red-400">User not found</div>
            )}
            {lookupStatus === 'found' && fingerprint && (
              <div className="space-y-1">
                <div className="text-[10px] font-medium tracking-wide text-zinc-500 uppercase dark:text-zinc-400">
                  Identity Key Fingerprint
                </div>
                <div className="font-mono text-xs leading-relaxed break-all text-indigo-600 dark:text-indigo-400">
                  {fingerprint}
                </div>
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={!recipientHandle.trim() || lookupStatus !== 'found'}
            className="w-full border border-[#0C0C0C] bg-[#0C0C0C] px-3 py-2 text-sm font-medium text-[#F2F6FC] hover:bg-transparent hover:text-[#0C0C0C] focus:ring-2 focus:ring-[#0C0C0C] focus:ring-offset-2 focus:ring-offset-[#F2F6FC] focus:outline-none disabled:cursor-not-allowed disabled:opacity-60 dark:border-[#F2F6FC] dark:bg-[#F2F6FC] dark:text-[#0C0C0C] dark:hover:bg-transparent dark:hover:text-[#F2F6FC] dark:focus:ring-[#F2F6FC] dark:focus:ring-offset-[#0C0C0C]"
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
  const [, setLocation] = useLocation();
  const [isLoading, setIsLoading] = useState(true);
  const [handle, setHandle] = useState<string | null>(null);
  const [keys, setKeys] = useState<KeyBundle | null>(null);
  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const [messages, setMessages] = useState();
  const [inputValue, setInputValue] = useState('');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [selectedContact, setSelectedContact] = useState<string>('alice');
  const [newConvoOpen, setNewConvoOpen] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Load identity on mount
  useEffect(() => {
    async function loadIdentity() {
      const [storedHandle, storedKeys] = await Promise.all([loadHandle(), loadKeys()]);

      if (!storedHandle || !storedKeys) {
        setLocation('/register');
        return;
      }

      setHandle(storedHandle);
      setKeys(storedKeys);
      setIsLoading(false);
    }

    loadIdentity();
  }, [setLocation]);

  useEffect(() => {
    if (!handle || !keys) return;

    function connect() {
      setStatus('connecting');

      const ws = new WebSocket(getWsUrl());
      ws.binaryType = 'arraybuffer';
      wsRef.current = ws;

      ws.onopen = () => {
        setStatus('authenticating');
      };

      ws.onmessage = event => {
        const data = new Uint8Array(event.data as ArrayBuffer);
        const envelope = websocket.Envelope.deserialize(data);

        switch (envelope.payload) {
          case 'challenge': {
            if (!keys || !handle) return;
            const nonce = envelope.challenge.nonce;
            const signature = xeddsaSign(keys.IK.privateKey, nonce, randomBytes(64));

            const response = new websocket.Envelope({
              challenge_response: new websocket.ChallengeResponse({
                handle,
                signature
              })
            });

            ws.send(response.serialize());
            setStatus('connected');
            break;
          }

          default:
            break;
        }
      };

      ws.onerror = () => {
        setStatus('error');
      };

      ws.onclose = () => {
        setStatus('disconnected');
        wsRef.current = null;
      };
    }

    connect();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [handle, keys]);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  function handleSend(e: FormEvent) {
    e.preventDefault();
    const content = inputValue.trim();
    if (!content) return;

    // const newMessage: Message = {
    //   id: crypto.randomUUID(),
    //   from: handle || 'me',
    //   content,
    //   timestamp: new Date(),
    //   isOwn: true
    // };

    // setMessages(prev => [...prev, newMessage]);
    // setInputValue('');
  }

  function handleStartConversation(recipientHandle: string) {
    setSelectedContact(recipientHandle);
    // setMessages([]);
    setNewConvoOpen(false);
  }

  function formatTime(date: Date): string {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function formatRelativeTime(date: Date): string {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const days = Math.floor(diff / 86400000);

    if (days === 0) return formatTime(date);
    if (days === 1) return 'Yesterday';
    if (days < 7) return date.toLocaleDateString([], { weekday: 'short' });
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
  }

  function getStatusText(): string {
    switch (status) {
      case 'connecting':
        return 'Connecting…';
      case 'authenticating':
        return 'Authenticating…';
      case 'connected':
        return 'Connected';
      case 'disconnected':
        return 'Disconnected';
      case 'error':
        return 'Connection error';
    }
  }

  function getStatusColor(): string {
    switch (status) {
      case 'connected':
        return 'bg-emerald-500';
      case 'connecting':
      case 'authenticating':
        return 'bg-amber-500';
      case 'disconnected':
      case 'error':
        return 'bg-red-500';
    }
  }

  if (isLoading) {
    return (
      <main className="min-h-screen bg-[#F2F6FC] text-[#0C0C0C] dark:bg-[#0C0C0C] dark:text-[#F2F6FC]">
        <div className="flex min-h-screen items-center justify-center">
          <div className="text-sm">Loading…</div>
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
        myHandle={handle}
        myKeys={keys}
      />
      <main className="flex h-screen bg-[#F2F6FC] text-[#0C0C0C] dark:bg-[#0C0C0C] dark:text-[#F2F6FC]">
        {/* Sidebar */}
        <aside
          className={`flex shrink-0 flex-col border-r border-[#0C0C0C] transition-all duration-200 dark:border-[#F2F6FC] ${
            sidebarOpen ? 'w-72' : 'w-0 overflow-hidden border-r-0'
          }`}
        >
          {/* Sidebar header */}
          <div className="flex shrink-0 items-center justify-between border-b border-[#0C0C0C] px-4 py-3 dark:border-[#F2F6FC]">
            <span className="text-sm font-semibold">Contacts</span>
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1.5 text-xs">
                <div className={`h-2 w-2 rounded-full ${getStatusColor()}`} />
                <span className="text-zinc-500 dark:text-zinc-400">{getStatusText()}</span>
              </div>
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

          {/* Contact list */}
          <div className="flex-1 overflow-y-auto">
            {/*MOCK_CONTACTS.map(contact => (
              <button
                key={contact.handle}
                onClick={() => setSelectedContact(contact.handle)}
                className={`flex w-full items-center gap-3 border-b border-[#0C0C0C] px-4 py-3 text-left transition-colors dark:border-[#F2F6FC] ${
                  selectedContact === contact.handle
                    ? 'bg-[#0C0C0C] text-[#F2F6FC] dark:bg-[#F2F6FC] dark:text-[#0C0C0C]'
                    : 'hover:bg-[#0C0C0C]/5 dark:hover:bg-[#F2F6FC]/5'
                }}
              >
                <div
                  className={`flex h-10 w-10 shrink-0 items-center justify-center border text-sm font-semibold uppercase ${
                    selectedContact === contact.handle
                      ? 'border-[#F2F6FC] dark:border-[#0C0C0C]'
                      : 'border-[#0C0C0C] dark:border-[#F2F6FC]'
                  }`}
                >
                  {contact.handle[0]}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium">{contact.handle}</span>
                    {contact.lastMessageTime && (
                      <span
                        className={`shrink-0 text-[10px] ${
                          selectedContact === contact.handle
                            ? 'text-zinc-400 dark:text-zinc-500'
                            : 'text-zinc-500 dark:text-zinc-400'
                        }`}
                      >
                        {formatRelativeTime(contact.lastMessageTime)}
                      </span>
                    )}
                  </div>
                  {contact.lastMessage && (
                    <p
                      className={`truncate text-xs ${
                        selectedContact === contact.handle
                          ? 'text-zinc-400 dark:text-zinc-500'
                          : 'text-zinc-500 dark:text-zinc-400'
                      }`}
                    >
                      {contact.lastMessage}
                    </p>
                  )}
                </div>
              </button>
            ))*/}
          </div>

          {/* Sidebar footer - identity */}
          <div className="shrink-0 border-t border-[#0C0C0C] px-4 py-3 dark:border-[#F2F6FC]">
            <div className="flex items-center gap-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center border border-[#0C0C0C] text-xs font-semibold uppercase dark:border-[#F2F6FC]">
                {handle?.[0] ?? '?'}
              </div>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium">{handle}</div>
                <div className="text-[10px] text-zinc-500 dark:text-zinc-400">
                  {keys?.OPKs.length ?? 0} <span title="One-time prekeys">OPKs</span> · {keys?.PQOPKs.length ?? 0}{' '}
                  <span title="Post-quantum one-time prekeys">PQOPKs</span>
                </div>
              </div>
            </div>
          </div>
        </aside>

        {/* Main chat area */}
        <div className="flex min-w-0 flex-1 flex-col">
          {/* Header */}
          <header className="flex shrink-0 items-center justify-between border-b border-[#0C0C0C] px-4 py-3 dark:border-[#F2F6FC]">
            <div className="flex items-center gap-3">
              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="flex h-8 w-8 items-center justify-center border border-[#0C0C0C] text-sm hover:bg-[#0C0C0C] hover:text-[#F2F6FC] dark:border-[#F2F6FC] dark:hover:bg-[#F2F6FC] dark:hover:text-[#0C0C0C]"
                aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
              >
                {sidebarOpen ? '✕' : '☰'}
              </button>
              <div className="flex h-8 w-8 items-center justify-center border border-[#0C0C0C] text-xs font-semibold uppercase dark:border-[#F2F6FC]">
                {selectedContact[0]}
              </div>
              <div className="text-sm font-semibold">{selectedContact}</div>
            </div>
          </header>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-4 py-4">
            <div className="mx-auto max-w-2xl space-y-3">
              {/*messages.map(msg => (
                <div key={msg.id} className={`flex ${msg.isOwn ? 'justify-end' : 'justify-start'}`}>
                  <div
                    className={`max-w-[75%] border px-3 py-2 ${
                      msg.isOwn
                        ? 'border-[#0C0C0C] bg-[#0C0C0C] text-[#F2F6FC] dark:border-[#F2F6FC] dark:bg-[#F2F6FC] dark:text-[#0C0C0C]'
                        : 'border-[#0C0C0C] bg-transparent dark:border-[#F2F6FC]'
                    }`}
                  >
                    <div className="text-sm">{msg.content}</div>
                    <div
                      className={`mt-1 text-right text-[10px] ${
                        msg.isOwn ? 'text-zinc-400 dark:text-zinc-500' : 'text-zinc-500 dark:text-zinc-400'
                      }`}
                    >
                      {formatTime(msg.timestamp)}
                    </div>
                  </div>
                </div>
              ))*/}
              <div ref={messagesEndRef} />
            </div>
          </div>

          {/* Input area */}
          <div className="shrink-0 border-t border-[#0C0C0C] px-4 py-3 dark:border-[#F2F6FC]">
            <div className="mx-auto max-w-2xl space-y-2">
              {/* Identity bar - moved above input */}
              <div className="flex items-center justify-between text-xs text-zinc-500 dark:text-zinc-400">
                <span>
                  Signed in as <span className="font-medium text-[#0C0C0C] dark:text-[#F2F6FC]">{handle}</span>
                </span>
                <span>
                  {keys?.OPKs.length ?? 0} OPKs · {keys?.PQOPKs.length ?? 0} PQOPKs
                </span>
              </div>

              {/* Input form */}
              <form onSubmit={handleSend} className="flex gap-2">
                <input
                  type="text"
                  value={inputValue}
                  onChange={e => setInputValue(e.target.value)}
                  placeholder="Type a message…"
                  className="flex-1 border border-[#0C0C0C] bg-transparent px-3 py-2 text-sm text-[#0C0C0C] placeholder:text-zinc-500 focus:ring-2 focus:ring-[#0C0C0C] focus:ring-offset-2 focus:ring-offset-[#F2F6FC] focus:outline-none dark:border-[#F2F6FC] dark:text-[#F2F6FC] dark:placeholder:text-zinc-400 dark:focus:ring-[#F2F6FC] dark:focus:ring-offset-[#0C0C0C]"
                />
                <button
                  type="submit"
                  disabled={!inputValue.trim()}
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

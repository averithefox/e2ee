import { Loader2, OctagonX, Plus, SidebarClose, SidebarOpen } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { MessageBubble } from '~/components/message-bubble';
import { MessageInput, type MessageInputHandle } from '~/components/message-input';
import NewConversationModal from '~/components/new-conversation-modal';
import { Button } from '~/components/ui/button';
import { useChat, type MessageData } from '~/hooks/use-chat';
import { cn, eq } from '~/lib/utils';

// Hook to detect mobile viewport
function useIsMobile(breakpoint = 768) {
  const [isMobile, setIsMobile] = useState(() =>
    typeof window !== 'undefined' ? window.innerWidth < breakpoint : false
  );

  useEffect(() => {
    const mql = window.matchMedia(`(max-width: ${breakpoint - 1}px)`);
    const onChange = (e: MediaQueryListEvent) => setIsMobile(e.matches);
    mql.addEventListener('change', onChange);
    setIsMobile(mql.matches);
    return () => mql.removeEventListener('change', onChange);
  }, [breakpoint]);

  return isMobile;
}

export function HomeView() {
  const {
    status,
    identity,
    selectedContact,
    setSelectedContact,
    contactsList,
    messages,
    sendNewMessage,
    editMessage,
    deleteMessage
  } = useChat();

  const isMobile = useIsMobile();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [newConvoOpen, setNewConvoOpen] = useState(false);
  const [replyingTo, setReplyingTo] = useState<MessageData | null>(null);
  const [highlightedMsgId, setHighlightedMsgId] = useState<Uint8Array | null>(null);

  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<MessageInputHandle>(null);

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

  const handleStartConversation = useCallback(
    (handle: string) => {
      setSelectedContact(handle);
      setReplyingTo(null);
      setNewConvoOpen(false);
    },
    [setSelectedContact]
  );

  const handleSelectContact = useCallback(
    (handle: string) => {
      setSelectedContact(handle);
      setReplyingTo(null);
      // Auto-close sidebar on mobile when selecting a contact
      if (isMobile) setSidebarOpen(false);
    },
    [setSelectedContact, isMobile]
  );

  const handleSend = useCallback(
    async (text: string, replyToId?: Uint8Array) => {
      const success = await sendNewMessage(text, replyToId);
      if (success) {
        setReplyingTo(null);
      }
      return success;
    },
    [sendNewMessage]
  );

  const handleReply = useCallback((msg: MessageData) => {
    setReplyingTo(msg);
    inputRef.current?.focus();
  }, []);

  // Loading/error state
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
        {/* Mobile backdrop */}
        {isMobile && sidebarOpen && (
          <div
            className="bg-background/80 fixed inset-0 z-40 backdrop-blur-sm"
            onClick={() => setSidebarOpen(false)}
            aria-hidden="true"
          />
        )}

        {/* Sidebar */}
        <aside
          className={cn(
            'bg-card border-border flex shrink-0 flex-col border-r transition-all duration-200',
            // Mobile: fixed overlay
            isMobile && 'fixed inset-y-0 left-0 z-50 shadow-xl',
            // Desktop: inline
            !isMobile && (sidebarOpen ? 'w-72' : 'w-0 overflow-hidden border-r-0'),
            // Mobile: slide in/out
            isMobile && (sidebarOpen ? 'w-72 translate-x-0' : 'w-72 -translate-x-full')
          )}
        >
          <div className="border-border flex h-14 shrink-0 items-center justify-between border-b px-4">
            <span className="text-sm font-semibold">Contacts</span>
            <div className="flex items-center gap-1">
              <Button
                variant="outline"
                size="icon-sm"
                onClick={() => setNewConvoOpen(true)}
                aria-label="New conversation"
                title="New conversation"
              >
                <Plus className="size-4" />
              </Button>
              {isMobile && (
                <Button variant="ghost" size="icon-sm" onClick={() => setSidebarOpen(false)} aria-label="Close sidebar">
                  <SidebarClose className="size-4" />
                </Button>
              )}
            </div>
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

        {/* Main chat area */}
        <div className="flex min-w-0 flex-1 flex-col">
          {/* Header */}
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
              <span className="text-sm font-semibold">{selectedContact}</span>
            ) : (
              <span className="text-muted-foreground text-sm">Select a conversation</span>
            )}
          </header>

          {/* Messages */}
          <div ref={messagesContainerRef} className="flex-1 overflow-y-auto px-2 py-3 sm:p-4">
            {!selectedContact ? (
              <div className="text-muted-foreground flex h-full items-center justify-center px-4 text-center text-sm">
                Select a contact to start chatting
              </div>
            ) : messages?.length === 0 ? (
              <div className="text-muted-foreground flex h-full items-center justify-center px-4 text-center text-sm">
                No messages yet. Say hello!
              </div>
            ) : (
              <div className="mx-auto max-w-2xl space-y-2 sm:space-y-3">
                {messages?.map(msg => (
                  <MessageBubble
                    key={Array.from(msg.id).join(',')}
                    message={msg}
                    isOwn={msg.sender === identity.handle}
                    isHighlighted={!!(highlightedMsgId && eq(highlightedMsgId, msg.id))}
                    repliedMessage={msg.replyTo ? (findMessageById(msg.replyTo) ?? null) : null}
                    onReply={() => handleReply(msg)}
                    onEdit={newText => editMessage(msg, newText)}
                    onDelete={() => deleteMessage(msg)}
                    onScrollToReply={() => msg.replyTo && scrollToMessage(msg.replyTo)}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Input */}
          <MessageInput
            ref={inputRef}
            placeholder={selectedContact ? `Message ${selectedContact}` : 'Select a contact first'}
            disabled={!selectedContact}
            replyingTo={replyingTo}
            identityHandle={identity?.handle ?? ''}
            onCancelReply={() => setReplyingTo(null)}
            onSend={handleSend}
          />
        </div>
      </main>
    </>
  );
}

export default HomeView;

import { Reply, X } from 'lucide-react';
import { forwardRef, useCallback, useEffect, useImperativeHandle, useRef } from 'react';
import type { MessageData } from '~/hooks/use-chat';
import { cn } from '~/lib/utils';
import { Button } from './ui/button';

const MIN_ROWS = 2;
const MAX_ROWS = 16;
const LINE_HEIGHT = 20; // Approximate line height in pixels

interface MessageInputProps {
  placeholder?: string;
  disabled?: boolean;
  replyingTo: MessageData | null;
  identityHandle: string;
  onCancelReply: () => void;
  onSend: (text: string, replyToId?: Uint8Array) => Promise<boolean>;
}

export interface MessageInputHandle {
  focus: () => void;
}

export const MessageInput = forwardRef<MessageInputHandle, MessageInputProps>(
  ({ placeholder, disabled, replyingTo, identityHandle, onCancelReply, onSend }, ref) => {
    const textareaRef = useRef<HTMLTextAreaElement>(null);

    useImperativeHandle(ref, () => ({
      focus: () => textareaRef.current?.focus()
    }));

    const adjustHeight = useCallback(() => {
      const textarea = textareaRef.current;
      if (!textarea) return;

      // Reset height to auto to get the correct scrollHeight
      textarea.style.height = 'auto';

      // Calculate rows based on scroll height
      const scrollHeight = textarea.scrollHeight;
      const minHeight = MIN_ROWS * LINE_HEIGHT;
      const maxHeight = MAX_ROWS * LINE_HEIGHT;

      // Clamp between min and max
      const newHeight = Math.min(Math.max(scrollHeight, minHeight), maxHeight);
      textarea.style.height = `${newHeight}px`;

      // Show scrollbar if content exceeds max height
      textarea.style.overflowY = scrollHeight > maxHeight ? 'auto' : 'hidden';
    }, []);

    // Adjust height on mount and when content changes
    useEffect(() => {
      adjustHeight();
    }, [adjustHeight]);

    const handleKeyDown = async (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      // Shift+Enter inserts newline (default behavior)
      // Enter alone sends the message
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        const text = textareaRef.current?.value;
        if (!text?.trim()) return;

        const success = await onSend(text.trim(), replyingTo?.id);
        if (success && textareaRef.current) {
          textareaRef.current.value = '';
          adjustHeight();
        }
      }
    };

    const handleInput = () => {
      adjustHeight();
    };

    return (
      <div className="shrink-0 p-2">
        {replyingTo && (
          <div className="bg-muted/50 border-primary mb-2 flex items-center gap-2 rounded-lg border-l-2 px-3 py-2">
            <Reply className="text-muted-foreground size-4 shrink-0" />
            <div className="min-w-0 flex-1">
              <p className="text-muted-foreground text-xs font-medium">
                Replying to {replyingTo.sender === identityHandle ? 'yourself' : replyingTo.sender}
              </p>
              <p className="truncate text-sm">{replyingTo.text}</p>
            </div>
            <Button variant="ghost" size="icon-sm" onClick={onCancelReply} aria-label="Cancel reply">
              <X className="size-4" />
            </Button>
          </div>
        )}
        <textarea
          ref={textareaRef}
          placeholder={placeholder}
          disabled={disabled}
          onKeyDown={handleKeyDown}
          onInput={handleInput}
          rows={MIN_ROWS}
          className={cn(
            'border-input bg-background ring-offset-background placeholder:text-muted-foreground focus-visible:ring-ring flex w-full resize-none rounded-md border px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50',
            'dark:bg-background'
          )}
          style={{
            minHeight: `${MIN_ROWS * LINE_HEIGHT}px`,
            maxHeight: `${MAX_ROWS * LINE_HEIGHT}px`,
            overflowY: 'hidden'
          }}
        />
      </div>
    );
  }
);

MessageInput.displayName = 'MessageInput';

import { Check, CornerDownLeft, Pencil, Reply, Trash2, X } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import Markdown from 'react-markdown';
import type { MessageData } from '~/hooks/use-chat';
import { cn } from '~/lib/utils';
import { Button } from './ui/button';

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

interface MessageBubbleProps {
  message: MessageData;
  isOwn: boolean;
  isHighlighted: boolean;
  repliedMessage: MessageData | null;
  onReply: () => void;
  onEdit: (newText: string) => Promise<boolean>;
  onDelete: () => void;
  onScrollToReply: () => void;
}

export function MessageBubble({
  message,
  isOwn,
  isHighlighted,
  repliedMessage,
  onReply,
  onEdit,
  onDelete,
  onScrollToReply
}: MessageBubbleProps) {
  const [isEditing, setIsEditing] = useState(false);
  const [editText, setEditText] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const idStr = Array.from(message.id).join(',');

  const handleStartEdit = useCallback(() => {
    setIsEditing(true);
    setEditText(message.text ?? '');
  }, [message.text]);

  const handleCancelEdit = useCallback(() => {
    setIsEditing(false);
    setEditText('');
  }, []);

  const handleSaveEdit = useCallback(async () => {
    if (!editText.trim()) return;
    const success = await onEdit(editText.trim());
    if (success) {
      setIsEditing(false);
      setEditText('');
    }
  }, [editText, onEdit]);

  // Auto-resize textarea and focus when editing starts
  useEffect(() => {
    if (isEditing && textareaRef.current) {
      textareaRef.current.focus();
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${textareaRef.current.scrollHeight}px`;
    }
  }, [isEditing, editText]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Escape') {
      handleCancelEdit();
    } else if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSaveEdit();
    }
  };

  return (
    <div data-msg-id={idStr} className={cn('group flex items-end gap-2', isOwn ? 'flex-row-reverse' : 'flex-row')}>
      <div
        className={cn(
          'max-w-[75%] transition-all duration-300',
          isHighlighted && 'ring-ring ring-offset-background scale-[1.02] ring-2 ring-offset-2'
        )}
      >
        {message.replyTo && (
          <button
            type="button"
            onClick={onScrollToReply}
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
                : 'deleted message'}
            </span>
          </button>
        )}

        <div
          className={cn(
            'rounded-lg text-sm',
            message.replyTo && 'rounded-t-none',
            isOwn ? 'bg-primary text-primary-foreground' : 'bg-muted text-foreground'
          )}
        >
          {isEditing ? (
            <div className="flex flex-col gap-2 p-2">
              <textarea
                ref={textareaRef}
                value={editText}
                onChange={e => {
                  setEditText(e.target.value);
                  e.target.style.height = 'auto';
                  e.target.style.height = `${e.target.scrollHeight}px`;
                }}
                onKeyDown={handleKeyDown}
                className={cn(
                  'w-full min-w-[200px] resize-none rounded border px-2 py-1.5 text-sm outline-none',
                  isOwn
                    ? 'border-primary-foreground/30 bg-primary-foreground/10 text-primary-foreground placeholder:text-primary-foreground/50'
                    : 'border-foreground/20 bg-background text-foreground'
                )}
                rows={1}
              />
              <div className="flex justify-end gap-1">
                <Button
                  type="button"
                  variant="ghost"
                  size="icon-sm"
                  onClick={handleSaveEdit}
                  className={cn('shrink-0', isOwn ? 'text-primary-foreground hover:bg-primary-foreground/20' : '')}
                  aria-label="Save edit"
                >
                  <Check className="size-3.5" />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon-sm"
                  onClick={handleCancelEdit}
                  className={cn('shrink-0', isOwn ? 'text-primary-foreground hover:bg-primary-foreground/20' : '')}
                  aria-label="Cancel edit"
                >
                  <X className="size-3.5" />
                </Button>
              </div>
            </div>
          ) : (
            <div className="px-3 py-2">
              <div
                className={cn(
                  'prose prose-sm max-w-none',
                  isOwn
                    ? 'prose-invert prose-p:text-primary-foreground prose-strong:text-primary-foreground prose-em:text-primary-foreground prose-code:text-primary-foreground prose-a:text-primary-foreground/90 prose-a:underline'
                    : 'prose-p:text-foreground prose-strong:text-foreground prose-em:text-foreground prose-code:text-foreground prose-a:text-foreground'
                )}
              >
                <Markdown>{message.text}</Markdown>
              </div>
              <p className={cn('mt-1 text-[10px]', isOwn ? 'text-primary-foreground/60' : 'text-muted-foreground')}>
                {formatTime(message.timestamp)}
                {message.editedAt && <span className="ml-1">(edited {formatTime(message.editedAt)})</span>}
              </p>
            </div>
          )}
        </div>
      </div>

      <div
        className={cn(
          'flex shrink-0 gap-0.5 transition-opacity',
          // On touch devices (no hover), always show with reduced opacity
          // On hover devices, show on hover
          !isEditing && 'opacity-60 sm:opacity-0 sm:group-hover:opacity-100'
        )}
      >
        <Button variant="ghost" size="icon-sm" onClick={onReply} aria-label="Reply to message">
          <Reply className="size-3.5" />
        </Button>
        {isOwn && (
          <>
            <Button variant="ghost" size="icon-sm" onClick={handleStartEdit} aria-label="Edit message">
              <Pencil className="size-3.5" />
            </Button>
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={onDelete}
              className="hover:text-destructive"
              aria-label="Delete message"
            >
              <Trash2 className="size-3.5" />
            </Button>
          </>
        )}
      </div>
    </div>
  );
}

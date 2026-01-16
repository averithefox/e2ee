import { CornerDownLeft } from 'lucide-react';
import Markdown from 'react-markdown';
import type { Message } from '~/lib/db';
import { cn } from '~/lib/utils';

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
  message: Message;
  isOwn: boolean;
  isHighlighted: boolean;
  repliedMessage: Message | null;
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
  onDelete,
  onScrollToReply
}: MessageBubbleProps) {
  return (
    <div data-msg-id={message.id} className={cn('group flex items-end gap-2', isOwn ? 'flex-row-reverse' : 'flex-row')}>
      <div
        className={cn(
          'max-w-[75%] transition-all duration-300',
          isHighlighted && 'ring-ring ring-offset-background scale-[1.02] ring-2 ring-offset-2'
        )}
      >
        {message.reply_to && (
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
            message.reply_to && 'rounded-t-none',
            isOwn ? 'bg-primary text-primary-foreground' : 'bg-muted text-foreground'
          )}
        >
          <div className="px-3 py-2">
            <div className={cn('prose prose-sm max-w-none', isOwn ? '' : 'prose-invert')}>
              <Markdown>{message.text}</Markdown>
            </div>
            <p className={cn('mt-1 text-[10px]', isOwn ? 'text-primary-foreground/60' : 'text-muted-foreground')}>
              {formatTime(message.timestamp)}
              {message.last_edited_at && <span className="ml-1">(edited {formatTime(message.last_edited_at)})</span>}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

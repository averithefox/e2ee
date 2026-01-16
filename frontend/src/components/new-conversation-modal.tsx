import { X } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { fetchKeyBundle } from '~/lib/api';
import { db } from '~/lib/db';
import { verifyKeyBundle } from '~/lib/protocol';
import { cn, eq, formatFingerprint, validateHandle } from '~/lib/utils';
import { Button } from './ui/button';
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Input } from './ui/input';
import { Label } from './ui/label';

export function NewConversationModal({
  isOpen,
  onClose,
  onStart
}: {
  isOpen: boolean;
  onClose: () => void;
  onStart: (handle: string, idKey: Uint8Array) => void;
}) {
  const [recipientHandle, setRecipientHandle] = useState('');
  const [idKey, setIdKey] = useState<Uint8Array | null>(null);
  const [storedIdKey, setStoredIdKey] = useState<Uint8Array | null>(null);
  const [lookupStatus, setLookupStatus] = useState<
    'idle' | 'loading' | 'found' | 'not_found' | 'invalid_signature' | 'invalid_handle'
  >('idle');
  const [handleError, setHandleError] = useState<string | null>(null);

  const inputRef = useRef<HTMLInputElement>(null);
  const cache = useRef(new Map<string, Awaited<ReturnType<typeof fetchKeyBundle>>>());

  function resetKeyState() {
    setIdKey(null);
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
      setHandleError(null);
      return;
    }

    const validationError = validateHandle(handle);
    if (validationError) {
      resetKeyState();
      setLookupStatus('invalid_handle');
      setHandleError(validationError);
      return;
    }
    setHandleError(null);

    const controller = new AbortController();
    setLookupStatus('loading');

    (async () => {
      try {
        let res = cache.current.get(handle);
        if (!res) {
          res = await fetchKeyBundle(handle, { signal: controller.signal }, true);
          cache.current.set(handle, res);
        }

        if (res.isErr()) {
          resetKeyState();
          setLookupStatus(res.error === 404 ? 'not_found' : 'idle');
          return;
        }

        const storedIdKey = await db.identity_keys.get(handle);
        setStoredIdKey(storedIdKey?.pub ?? null);

        setIdKey(res.value.id_key);
        setLookupStatus('found');
      } catch (err) {
        if ((err as Error).name !== 'AbortError') {
          console.error(err);
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
    if (h && idKey && lookupStatus === 'found') {
      await db.identity_keys.put({ for: h, pub: idKey }, h);
      onStart(h, idKey);
      cache.current.delete(h);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-[#0C0C0C]/50 dark:bg-[#F2F6FC]/10" onClick={onClose} />
      <Card className="relative w-full max-w-sm">
        <CardHeader>
          <CardTitle>New Conversation</CardTitle>
          <CardDescription>Enter recipient handle</CardDescription>
          <CardAction>
            <Button type="button" variant="ghost" onClick={onClose}>
              <X className="size-4" />
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit}>
            <div className="flex flex-col gap-2">
              <div className="grid gap-2">
                <Label htmlFor="handle">Handle</Label>
                <Input
                  ref={inputRef}
                  type="text"
                  id="handle"
                  value={recipientHandle}
                  onChange={e => setRecipientHandle(e.target.value)}
                  autoFocus
                />
              </div>
              <div>
                {
                  {
                    loading: <div className="text-xs text-zinc-500 dark:text-zinc-400">Looking up identity…</div>,
                    not_found: <div className="text-xs text-red-600 dark:text-red-400">User not found</div>,
                    invalid_signature: <div className="text-xs text-red-600 dark:text-red-400">Invalid signature</div>,
                    invalid_handle: <div className="text-xs text-red-600 dark:text-red-400">{handleError}</div>,
                    idle: null,
                    found: idKey && (
                      <div className="space-y-1">
                        <div className="text-[10px] font-medium tracking-wide text-zinc-500 uppercase dark:text-zinc-400">
                          Identity Key Fingerprint
                        </div>
                        <p
                          className={cn(
                            'font-mono text-xs leading-relaxed break-all',
                            !storedIdKey || eq(idKey, storedIdKey)
                              ? 'text-indigo-600 dark:text-indigo-400'
                              : 'text-red-600 dark:text-red-400'
                          )}
                        >
                          {formatFingerprint(idKey)}
                        </p>
                      </div>
                    )
                  }[lookupStatus]
                }
              </div>

              {idKey && storedIdKey && !eq(idKey, storedIdKey) && (
                <div className="w-full space-y-2 bg-red-600 p-2 text-sm text-white dark:bg-red-400">
                  <p>
                    The identity key provided by the server does not match {recipientHandle}'
                    {recipientHandle.endsWith('s') ? '' : 's'} last known identity key.
                  </p>
                  <p className="font-mono text-xs leading-relaxed break-all">{formatFingerprint(storedIdKey)}</p>
                </div>
              )}

              <Button type="submit" disabled={!recipientHandle.trim() || lookupStatus !== 'found'}>
                Start
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

export default NewConversationModal;

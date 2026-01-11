import type { messages } from 'generated/messages';
import type { Result } from 'neverthrow';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { fetchKeyBundle } from '~/lib/api';
import { db } from '~/lib/db';
import { verifyKeyBundle } from '~/lib/protocol';
import { cn, eq, formatFingerprint } from '~/lib/utils';

export function NewConversationModal({
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

  const keyBundleCache = useRef(new Map<string, Result<messages.PQXDHKeyBundle, number>>());

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
        let res = keyBundleCache.current.get(handle);
        if (!res) {
          res = await fetchKeyBundle(handle, { signal: controller.signal });
          keyBundleCache.current.set(handle, res);
        }

        if (res.isErr()) {
          resetKeyState();
          setLookupStatus(res.error === 404 ? 'not_found' : 'idle');
          return;
        }

        if (!verifyKeyBundle(res.value)) {
          resetKeyState();
          setLookupStatus('invalid_signature');
          return;
        }

        const storedIdKey = await db.identity_keys.get(handle);
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
      keyBundleCache.current.delete(h);
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

export default NewConversationModal;

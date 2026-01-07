import { x25519 } from '@noble/curves/ed25519.js';
import { messages } from 'generated/messages';
import { MlKem1024 } from 'mlkem';
import { useRef, useState, type FormEvent } from 'react';
import { useLocation } from 'wouter';
import { randomBytes, xeddsaSign } from '~/lib/crypto';
import { storeHandle, storeKeys, type KeyBundle } from '~/lib/storage';
import { API_BASE_URL } from '~/lib/utils';

function x25519KeyPair() {
  const privateKey = randomBytes(32);
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

async function genKeys(): Promise<KeyBundle> {
  const kem = new MlKem1024();
  let nextId = 0;

  const IK = x25519KeyPair();
  const SPK = x25519KeyPair();
  const SPK_sig = xeddsaSign(IK.privateKey, SPK.publicKey, randomBytes(64));
  const [PQSPK_publicKey, PQSPK_privateKey] = await kem.generateKeyPair();
  const PQSPK_sig = xeddsaSign(IK.privateKey, PQSPK_publicKey, randomBytes(64));
  const OPKs = Array.from({ length: 100 }, () => x25519KeyPair());
  const PQOPKs = await Promise.all(
    Array.from({ length: 100 }, async () => {
      const [publicKey, privateKey] = await kem.generateKeyPair();
      return { publicKey, privateKey };
    })
  );

  return {
    IK,
    SPK: {
      publicKey: SPK.publicKey,
      privateKey: SPK.privateKey,
      id: nextId++,
      sig: SPK_sig
    },
    PQPSK: {
      publicKey: PQSPK_publicKey,
      privateKey: PQSPK_privateKey,
      id: nextId++,
      sig: PQSPK_sig
    },
    OPKs: OPKs.map(({ publicKey, privateKey }) => ({
      publicKey,
      privateKey,
      id: nextId++
    })),
    PQOPKs: PQOPKs.map(({ publicKey, privateKey }) => ({
      publicKey,
      privateKey,
      id: nextId++,
      sig: xeddsaSign(IK.privateKey, publicKey, randomBytes(64))
    })),
    nextKeyId: nextId
  };
}

export function RegisterView() {
  const inputRef = useRef<HTMLInputElement>(null!);
  const [, setLocation] = useLocation();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleRegister(e: FormEvent) {
    e.preventDefault();
    if (isSubmitting) return;
    setError(null);

    const handle = inputRef.current.value.trim();
    if (!handle) {
      setError('Please enter a handle.');
      inputRef.current.focus();
      return;
    }

    setIsSubmitting(true);
    try {
      const keys = await genKeys();
      const pb = new messages.Identity({
        handle,
        id_key: keys.IK.publicKey,
        prekey: new messages.SignedPrekey({
          key: keys.SPK.publicKey,
          id: keys.SPK.id,
          sig: keys.SPK.sig
        }),
        pqkem_prekey: new messages.SignedPrekey({
          key: keys.PQPSK.publicKey,
          id: keys.PQPSK.id,
          sig: keys.PQPSK.sig
        }),
        one_time_pqkem_prekeys: keys.PQOPKs.map(
          pqopk =>
            new messages.SignedPrekey({
              key: pqopk.publicKey,
              id: pqopk.id,
              sig: pqopk.sig
            })
        ),
        one_time_prekeys: keys.OPKs.map(
          opk =>
            new messages.Prekey({
              key: opk.publicKey,
              id: opk.id
            })
        )
      });

      const buf = pb.serialize();
      const res = await fetch(`${API_BASE_URL}/api/identity`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream'
        },
        body: buf
      });

      if (!res.ok) {
        throw new Error(`Registration failed (${res.status})`);
      }

      await storeKeys(keys);
      await storeHandle(handle);
      setLocation('/');
    } catch (err) {
      console.error(err);
      setError('An error occurred while registering. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#F2F6FC] text-[#0C0C0C] dark:bg-[#0C0C0C] dark:text-[#F2F6FC]">
      <div className="mx-auto flex min-h-screen w-full max-w-md flex-col justify-center px-6">
        <div className="border border-[#0C0C0C] bg-[#F2F6FC] p-6 dark:border-[#F2F6FC] dark:bg-[#0C0C0C]">
          <h1 className="text-xl font-semibold tracking-tight">Register</h1>
          <form className="mt-3 space-y-3" onSubmit={handleRegister}>
            <label className="block">
              <span className="sr-only">Handle</span>
              <input
                type="text"
                placeholder="Handle"
                ref={inputRef}
                autoFocus
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                className="w-full border border-[#0C0C0C] bg-transparent px-3 py-2 text-sm text-[#0C0C0C] placeholder:text-zinc-500 focus:ring-2 focus:ring-[#0C0C0C] focus:ring-offset-2 focus:ring-offset-[#F2F6FC] focus:outline-none dark:border-[#F2F6FC] dark:text-[#F2F6FC] dark:placeholder:text-zinc-400 dark:focus:ring-[#F2F6FC] dark:focus:ring-offset-[#0C0C0C]"
              />
            </label>

            {error ? (
              <div className="border border-[#0C0C0C] bg-[#0C0C0C] px-3 py-2 text-sm text-[#F2F6FC] dark:border-[#F2F6FC] dark:bg-[#F2F6FC] dark:text-[#0C0C0C]">
                {error}
              </div>
            ) : null}

            <button
              type="submit"
              disabled={isSubmitting}
              className="inline-flex w-full items-center justify-center border border-[#0C0C0C] bg-[#0C0C0C] px-3 py-2 text-sm font-medium text-[#F2F6FC] hover:bg-transparent hover:text-[#0C0C0C] focus:ring-2 focus:ring-[#0C0C0C] focus:ring-offset-2 focus:ring-offset-[#F2F6FC] focus:outline-none disabled:cursor-not-allowed disabled:opacity-60 dark:border-[#F2F6FC] dark:bg-[#F2F6FC] dark:text-[#0C0C0C] dark:hover:bg-transparent dark:hover:text-[#F2F6FC] dark:focus:ring-[#F2F6FC] dark:focus:ring-offset-[#0C0C0C]"
            >
              {isSubmitting ? 'Registering…' : 'Register'}
            </button>
          </form>
        </div>
      </div>
    </main>
  );
}

export default RegisterView;

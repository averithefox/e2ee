import { useRef, useState, type FormEvent } from 'react';
import { useLocation } from 'wouter';
import { registerIdentity } from '~/lib/api';

export function RegisterView() {
  const [, navigate] = useLocation();

  const inputRef = useRef<HTMLInputElement>(null!);
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
      await registerIdentity(handle);
      return navigate('/');
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
              Register
            </button>
          </form>
        </div>
      </div>
    </main>
  );
}

export default RegisterView;

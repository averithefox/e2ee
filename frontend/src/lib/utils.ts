import { type ClassValue, clsx } from 'clsx';
import type { Result } from 'neverthrow';
import { twMerge } from 'tailwind-merge';

export type ResultPromise<T, E> = Promise<Result<T, E>>;
export type Nullish<T> = T | null | undefined;

export type EnhancedOmit<T, K extends keyof T> = string extends keyof T
  ? T
  : T extends any
    ? Pick<T, Exclude<keyof T, K>>
    : never;

export function concat(...arrays: Uint8Array[]) {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

export function eq(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export function b64Encode(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes));
}

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatFingerprint(key: Uint8Array): string {
  const hex = Array.from(key)
    .map(b => b.toString(16).padStart(2, '0').toUpperCase())
    .join('');
  // Group into 4-char chunks separated by spaces
  return hex.match(/.{1,4}/g)?.join(' ') ?? hex;
}

export async function _sleep(ms: number) {
  if (process.env.NODE_ENV !== 'development') return;
  return new Promise(resolve => setTimeout(resolve, ms));
}

const HANDLE_MIN_LENGTH = 3;
const HANDLE_MAX_LENGTH = 32;
const HANDLE_REGEX = /^[a-z][a-z0-9_]*$/;

export function validateHandle(handle: string): string | null {
  if (!handle) return 'Handle is required';
  if (handle.length < HANDLE_MIN_LENGTH) return `Handle must be at least ${HANDLE_MIN_LENGTH} characters`;
  if (handle.length > HANDLE_MAX_LENGTH) return `Handle must be at most ${HANDLE_MAX_LENGTH} characters`;
  if (handle !== handle.toLowerCase()) return 'Handle must be lowercase';
  if (!HANDLE_REGEX.test(handle))
    return 'Handle must start with a letter and contain only letters, numbers, and underscores';
  if (handle.includes('__')) return 'Handle cannot contain consecutive underscores';
  if (handle.endsWith('_')) return 'Handle cannot end with an underscore';
  return null;
}

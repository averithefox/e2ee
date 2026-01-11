import { type ClassValue, clsx } from 'clsx';
import type { Result } from 'neverthrow';
import { twMerge } from 'tailwind-merge';

export type ResultPromise<T, E> = Promise<Result<T, E>>;

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

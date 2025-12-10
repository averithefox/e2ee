import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function b64Decode(b64: string) {
  const bytes = atob(b64);
  return new Uint8Array(bytes.split('').map(char => char.charCodeAt(0)));
}

export function b64Encode(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes));
}

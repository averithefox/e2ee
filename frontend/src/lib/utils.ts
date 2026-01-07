import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { randomBytes, xeddsaSign } from './crypto';

export const API_BASE_URL = process.env.NODE_ENV === 'development' ? 'http://localhost:8000' : '';

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

export async function $fetch(
  url: string,
  {
    identity,
    method = 'GET',
    body,
    ...rest
  }: RequestInit & { body?: Uint8Array | null; identity: { handle: string; privateKey: Uint8Array } }
) {
  const urlObj = new URL(url);
  const pathname = urlObj.pathname;
  const query = urlObj.search.slice(1); // Remove leading '?'

  // method + uri + query + body
  const methodBytes = new TextEncoder().encode(method.toUpperCase());
  const uriBytes = new TextEncoder().encode(pathname);
  const queryBytes = new TextEncoder().encode(query);
  const bodyBytes = body ?? new Uint8Array(0);

  const messageParts = [methodBytes, uriBytes, queryBytes, bodyBytes];
  const totalLength = messageParts.reduce((sum, part) => sum + part.length, 0);
  const message = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of messageParts) {
    message.set(part, offset);
    offset += part.length;
  }

  const signature = xeddsaSign(identity.privateKey, message, randomBytes(64));
  const signatureB64 = b64Encode(signature);

  const headers = new Headers(rest.headers);
  headers.set('X-Identity', identity.handle);
  headers.set('X-Signature', signatureB64);

  return fetch(url, {
    ...rest,
    method,
    body,
    headers
  });
}

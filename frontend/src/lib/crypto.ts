import type { Message } from 'google-protobuf';
import { b64Encode } from './utils';

export function genEncKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 4096,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
      hash: 'SHA-512'
    },
    true, // extractable
    ['encrypt', 'decrypt']
  );
}

export function genSigKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 4096,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
      hash: 'SHA-512'
    },
    true, // extractable
    ['sign', 'verify']
  );
}

export async function yeet(path: string, msg: Message) {
  const bytes = msg.serializeBinary();
  const [identity, keyStr] = [localStorage.getItem('handle'), localStorage.getItem('sig_priv')];
  if (!identity || !keyStr) {
    return fetch(path, {
      method: 'POST',
      body: bytes
    });
  }

  const jwk = JSON.parse(keyStr);
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-512'
    },
    false,
    ['sign']
  );

  // See: verify_request() in backend/src/util.c
  const encoder = new TextEncoder();

  const url = new URL(path, window.location.origin);
  const methodBytes = encoder.encode('POST');
  const uriBytes = encoder.encode(url.pathname + url.search);

  const parts = [methodBytes, uriBytes, bytes];
  const msgToSign = new Uint8Array(parts.reduce((acc, part) => acc + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    msgToSign.set(part, offset);
    offset += part.length;
  }

  const sigBuf = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, msgToSign);
  const sigB64 = b64Encode(new Uint8Array(sigBuf));

  return fetch(path, {
    method: 'POST',
    body: bytes,
    headers: {
      'X-Identity': identity,
      'X-Signature': sigB64
    }
  });
}

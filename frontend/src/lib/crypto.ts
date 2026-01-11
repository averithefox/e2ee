import { Point, etc, hashes } from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

hashes.sha512 = sha512;
const { p, n: q } = Point.CURVE();
const { mod, invert, concatBytes, randomBytes } = etc;

export { randomBytes };

// Bytes <-> BigInt (little-endian)
const toN = (b: Uint8Array) => b.reduce((n, x, i) => n | (BigInt(x) << BigInt(i * 8)), 0n);
const toB = (n: bigint, len = 32) => Uint8Array.from({ length: len }, (_, i) => Number((n >> BigInt(i * 8)) & 0xffn));

// XEdDSA hashes (Section 5): hash1 has 0xFE×32 prefix for nonce, hash is plain SHA-512
const hash1 = (...d: Uint8Array[]) => mod(toN(sha512(concatBytes(new Uint8Array(32).fill(0xff), ...d))), q);
const xhash = (...d: Uint8Array[]) => mod(toN(sha512(concatBytes(...d))), q);

// Clamp scalar per RFC 7748
const clamp = (k: Uint8Array) => {
  const c = new Uint8Array(k);
  c[0]! &= 248;
  c[31]! &= 127;
  c[31]! |= 64;
  return c;
};

// Montgomery u -> Edwards y: y = (u-1)/(u+1)
const uToY = (u: bigint) => mod((u - 1n) * invert(u + 1n, p), p);

// Convert X25519 public key (u-coord) to Edwards point with sign=0
const convertMont = (u: bigint) => {
  const yBytes = toB(uToY(mod(u, 2n ** 255n)));
  yBytes[31]! &= 0x7f;
  return Point.fromBytes(yBytes);
};

// Convert X25519 private key to Edwards keypair (A, a) with sign=0
const calcKeyPair = (k: bigint) => {
  const kq = mod(k, q),
    E = Point.BASE.multiply(kq),
    { x } = E.toAffine();
  return x & 1n ? { A: E.negate(), a: mod(-kq, q) } : { A: E, a: kq };
};

// XEdDSA Sign: k=X25519 private key, M=message, Z=64 random bytes
export function xeddsa_sign(k: Uint8Array, M: Uint8Array, Z: Uint8Array): Uint8Array {
  const { A, a } = calcKeyPair(toN(clamp(k)));
  const r = hash1(toB(a), M, Z);
  const R = Point.BASE.multiply(r);
  const h = xhash(R.toBytes(), A.toBytes(), M);
  return concatBytes(R.toBytes(), toB(mod(r + h * a, q)));
}

// XEdDSA Verify: u=X25519 public key, M=message, sig=64-byte signature
export function xeddsa_verify(u: Uint8Array, M: Uint8Array, sig: Uint8Array): boolean {
  if (sig.length !== 64 || u.length !== 32) return false;
  const [R_b, s_b] = [sig.slice(0, 32), sig.slice(32)];
  const [uN, s] = [toN(u), toN(s_b)];
  if (uN >= p || s >= q) return false;
  try {
    const [R, A] = [Point.fromBytes(R_b), convertMont(uN)];
    const h = xhash(R_b, A.toBytes(), M);
    return R.equals(Point.BASE.multiply(s).subtract(A.multiply(h)));
  } catch {
    return false;
  }
}

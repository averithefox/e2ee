declare const PUBLIC_KEY: string;

let cachedCryptoKey: CryptoKey | null = null;

async function getPublicKey(): Promise<CryptoKey> {
  if (cachedCryptoKey) return cachedCryptoKey;

  const binaryDer = Uint8Array.from(atob(PUBLIC_KEY), c => c.charCodeAt(0));

  cachedCryptoKey = await crypto.subtle.importKey(
    'spki',
    binaryDer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );

  return cachedCryptoKey;
}

async function verifySignature(data: ArrayBuffer, signature: ArrayBuffer): Promise<boolean> {
  const publicKey = await getPublicKey();
  return crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signature, data);
}

async function fetchWithSignatureVerification(request: Request): Promise<Response> {
  const url = new URL(request.url);

  if (
    url.pathname.endsWith('.sig') ||
    url.pathname.endsWith('.map') ||
    url.pathname.startsWith('/api/') ||
    url.origin !== self.location.origin
  ) {
    return fetch(request);
  }

  const lastSegment = url.pathname.split('/').pop() || '';
  const hasExtension = lastSegment.includes('.');
  const sigUrl = hasExtension ? `${request.url}.sig` : `${url.origin}/index.html.sig`;

  const [assetResponse, sigResponse] = await Promise.all([fetch(request), fetch(sigUrl).catch(() => null)]);

  if (!sigResponse || !sigResponse.ok) {
    console.error(`No signature found for ${url.pathname}`);
    return new Response(`No signature found for ${url.pathname}`, { status: 403 });
  }

  const [assetData, signatureData] = await Promise.all([
    assetResponse.clone().arrayBuffer(),
    sigResponse.arrayBuffer()
  ]);

  const isValid = await verifySignature(assetData, signatureData);

  if (!isValid) {
    console.error(`Invalid signature for ${url.pathname}`);
    return new Response(`Invalid signature for ${url.pathname}`, { status: 403 });
  }

  return assetResponse;
}

self.addEventListener('fetch', (event: FetchEvent) => {
  event.respondWith(fetchWithSignatureVerification(event.request));
});

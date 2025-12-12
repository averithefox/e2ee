import { Identity } from 'generated/messages';
import { genEncKeyPair, genSigKeyPair, yeet } from '../lib/crypto';

async function func() {
  const handle = 'rawr_x3';

  const [encKeyPair, sigKeyPair] = await Promise.all([genEncKeyPair(), genSigKeyPair()]);

  const [pubEncKeyBuf, pubSigKeyBuf] = await Promise.all([
    crypto.subtle.exportKey('spki', encKeyPair.publicKey),
    crypto.subtle.exportKey('spki', sigKeyPair.publicKey)
  ]);

  const id = new Identity({
    username: handle,
    pub_enc_key: new Uint8Array(pubEncKeyBuf),
    pub_sig_key: new Uint8Array(pubSigKeyBuf)
  });

  const res = await yeet('http://localhost:3000/api/new-identity', id, sigKeyPair.privateKey);

  if (!res.ok) {
    console.error('Failed to register identity', res.status, res.statusText);
    return;
  }

  const [encPrivJwk, sigPrivJwk] = await Promise.all([
    crypto.subtle.exportKey('jwk', encKeyPair.privateKey),
    crypto.subtle.exportKey('jwk', sigKeyPair.privateKey)
  ]);

  localStorage.setItem('handle', handle);
  localStorage.setItem('enc_priv', JSON.stringify(encPrivJwk));
  localStorage.setItem('sig_priv', JSON.stringify(sigPrivJwk));
}

export function TestView() {
  return (
    <button onClick={func} className="[all:unset]">
      Test
    </button>
  );
}

export default TestView;

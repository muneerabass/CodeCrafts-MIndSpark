// Cross-checks web/lib/vault-crypto.ts with internal/vaultcrypto (Go).
//   node scripts/vault-vectors.ts write  → internal/vaultcrypto/testdata/js_vectors.json (decrypted by the Go tests)
//   node scripts/vault-vectors.ts verify → decrypts internal/vaultcrypto/testdata/go_vectors.json (written by the Go tests)
import { readFileSync, writeFileSync } from 'node:fs';
import { decryptItem, encryptItem, fingerprints, newMember, newVaultKey, parseEnv, unwrapKey, unwrapPrivate, wrapKey } from '../lib/vault-crypto.ts';

const dir = new URL('../../internal/vaultcrypto/testdata/', import.meta.url);
const env = 'export STRIPE_KEY="sk_live_abc\\n123 \\"q\\""\n# c\nDB_URL=postgres://u:p@h/db # note\nSHORT=x\nPEM="-----BEGIN-----\nline2\n-----END-----"\nSINGLE=\'a #b\'\n';
const mode = process.argv[2];

if (mode === 'write') {
  const m = await newMember('correct horse battery staple', 100_000);
  const vk = newVaultKey();
  const wrapped = await wrapKey(vk, m.publicKey, 'proj1', 'user1');
  const item = await encryptItem(vk, new TextEncoder().encode(env), 'proj1', '.env.production');
  writeFileSync(new URL('js_vectors.json', dir), JSON.stringify({ passphrase: 'correct horse battery staple', public_key: m.publicKey, wrapped_private: m.wrapped, wrapped_key: wrapped, item, env, parsed: parseEnv(env), fingerprints: await fingerprints(env) }, null, 2) + '\n');
  console.log('wrote js_vectors.json');
} else if (mode === 'verify') {
  const g = JSON.parse(readFileSync(new URL('go_vectors.json', dir), 'utf8'));
  const priv = await unwrapPrivate(g.wrapped_private, g.passphrase);
  const vk = await unwrapKey(priv, g.wrapped_key, 'proj1', 'user1');
  const text = new TextDecoder().decode(await decryptItem(vk, g.item.iv, g.item.ciphertext, 'proj1', '.env.production'));
  if (text !== g.env) throw new Error('item mismatch');
  if (JSON.stringify(parseEnv(text)) !== JSON.stringify(g.parsed)) throw new Error('parseEnv mismatch: ' + JSON.stringify(parseEnv(text)));
  if (JSON.stringify(await fingerprints(text)) !== JSON.stringify(g.fingerprints)) throw new Error('fingerprint mismatch');
  let wrongOk = false;
  try {
    await unwrapPrivate(g.wrapped_private, 'wrong');
  } catch {
    wrongOk = true;
  }
  if (!wrongOk) throw new Error('wrong passphrase accepted');
  console.log('go_vectors.json verified in WebCrypto');
} else throw new Error('usage: write | verify');

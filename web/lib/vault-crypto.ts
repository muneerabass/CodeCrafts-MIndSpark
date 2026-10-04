// End-to-end encryption of the project vault, in the browser (WebCrypto).
// Byte-compatible with internal/vaultcrypto (Go, used by the CLI); the Go tests
// decrypt vectors produced by this file (scripts/vault-vectors.ts).
//   member key pair : ECDH P-256; PKCS#8 private key sealed with the passphrase (PBKDF2-SHA256 → AES-256-GCM)
//   vault key       : 32 random bytes per project, wrapped per member (ECDH → HKDF-SHA256 → AES-256-GCM)
//   item            : AES-256-GCM(vault key), bound to project id and item name

export type WrappedPrivate = { salt: string; iterations: number; iv: string; ciphertext: string };
export type WrappedKey = { ephemeral_public: string; iv: string; ciphertext: string };

export const ITERATIONS = 600_000;
const MEMBER_AAD = 'depguard-vault-member-v1';
const KEY_INFO = 'depguard-vault-key-v1';
const ITEM_AAD = 'depguard-vault-item-v1';

const subtle = () => globalThis.crypto.subtle;
const enc = (s: string) => new TextEncoder().encode(s);
export const b64 = (b: ArrayBuffer | Uint8Array) => {
  const u = b instanceof Uint8Array ? b : new Uint8Array(b);
  let s = '';
  for (const c of u) s += String.fromCharCode(c);
  return btoa(s);
};
export const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const random = (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n));
const ECDH = { name: 'ECDH', namedCurve: 'P-256' } as const;

async function aes(raw: Uint8Array) {
  return subtle().importKey('raw', raw as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function seal(key: CryptoKey, data: Uint8Array, aad?: Uint8Array) {
  const iv = random(12);
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv, ...(aad && { additionalData: aad }) } as AesGcmParams, key, data as BufferSource);
  return { iv: b64(iv), ciphertext: b64(ct) };
}
async function open(key: CryptoKey, iv: string, ct: string, aad?: Uint8Array) {
  return new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: unb64(iv), ...(aad && { additionalData: aad }) } as AesGcmParams, key, unb64(ct) as BufferSource));
}

async function passKey(passphrase: string, salt: Uint8Array, iterations: number) {
  const base = await subtle().importKey('raw', enc(passphrase), 'PBKDF2', false, ['deriveKey']);
  return subtle().deriveKey({ name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Creates a member key pair; the private key is sealed with the passphrase. */
export async function newMember(passphrase: string, iterations = ITERATIONS) {
  const kp = (await subtle().generateKey(ECDH, true, ['deriveBits'])) as CryptoKeyPair;
  const der = new Uint8Array(await subtle().exportKey('pkcs8', kp.privateKey));
  const salt = random(16);
  const sealed = await seal(await passKey(passphrase, salt, iterations), der, enc(MEMBER_AAD));
  const publicKey = b64(await subtle().exportKey('raw', kp.publicKey));
  const wrapped: WrappedPrivate = { salt: b64(salt), iterations, ...sealed };
  return { privateKey: await importPrivate(der), publicKey, wrapped };
}

async function importPrivate(der: Uint8Array) {
  return subtle().importKey('pkcs8', der as BufferSource, ECDH, false, ['deriveBits']);
}

/** Opens the member's private key; throws on a wrong passphrase. */
export async function unwrapPrivate(w: WrappedPrivate, passphrase: string) {
  let der: Uint8Array;
  try {
    der = await open(await passKey(passphrase, unb64(w.salt), w.iterations), w.iv, w.ciphertext, enc(MEMBER_AAD));
  } catch {
    throw new Error('Wrong vault passphrase');
  }
  return importPrivate(der);
}

async function kek(shared: ArrayBuffer, ephPub: Uint8Array, projectId: string, userId: string) {
  const ikm = await subtle().importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const bits = await subtle().deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: ephPub as BufferSource, info: enc(`${KEY_INFO}|${projectId}|${userId}`) }, ikm, 256);
  return aes(new Uint8Array(bits));
}

export const newVaultKey = () => random(32);

/** Seals a project vault key for a member's public key. */
export async function wrapKey(vaultKey: Uint8Array, memberPublic: string, projectId: string, userId: string): Promise<WrappedKey> {
  const pub = await subtle().importKey('raw', unb64(memberPublic) as BufferSource, ECDH, false, []);
  const eph = (await subtle().generateKey(ECDH, true, ['deriveBits'])) as CryptoKeyPair;
  const shared = await subtle().deriveBits({ name: 'ECDH', public: pub }, eph.privateKey, 256);
  const ephPub = new Uint8Array(await subtle().exportKey('raw', eph.publicKey));
  const sealed = await seal(await kek(shared, ephPub, projectId, userId), vaultKey);
  return { ephemeral_public: b64(ephPub), ...sealed };
}

/** Opens the vault key wrapped for this member. */
export async function unwrapKey(priv: CryptoKey, w: WrappedKey, projectId: string, userId: string) {
  const raw = unb64(w.ephemeral_public);
  const eph = await subtle().importKey('raw', raw as BufferSource, ECDH, false, []);
  const shared = await subtle().deriveBits({ name: 'ECDH', public: eph }, priv, 256);
  return open(await kek(shared, raw, projectId, userId), w.iv, w.ciphertext);
}

const itemAD = (projectId: string, name: string) => enc(`${ITEM_AAD}|${projectId}|${name}`);

export async function encryptItem(vaultKey: Uint8Array, plaintext: Uint8Array, projectId: string, name: string) {
  return seal(await aes(vaultKey), plaintext, itemAD(projectId, name));
}

export async function decryptItem(vaultKey: Uint8Array, iv: string, ct: string, projectId: string, name: string) {
  return open(await aes(vaultKey), iv, ct, itemAD(projectId, name));
}

/** SHA-256 (hex) of a secret value, used to match leaked keys without revealing them. */
export async function fingerprint(value: string) {
  const d = new Uint8Array(await subtle().digest('SHA-256', enc(value)));
  return [...d].map((x) => x.toString(16).padStart(2, '0')).join('');
}

export type EnvVar = { key: string; value: string };

/** Reads a .env file; same rules as vaultcrypto.ParseEnv in Go. */
export function parseEnv(src: string): EnvVar[] {
  const out: EnvVar[] = [];
  const lines = src.replaceAll('\r\n', '\n').split('\n');
  const closed = (s: string) => {
    for (let i = 0; i < s.length; i++) {
      if (s[i] === '\\') i++;
      else if (s[i] === '"') return true;
    }
    return false;
  };
  const unescape = (s: string) => {
    let r = '';
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '"') break;
      if (c === '\\' && i + 1 < s.length) {
        const n = s[++i];
        r += n === 'n' ? '\n' : n === 't' ? '\t' : n;
        continue;
      }
      r += c;
    }
    return r;
  };
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('export ')) line = line.slice(7);
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_.]*$/.test(key)) continue;
    let v = line.slice(eq + 1).trim();
    if (v.startsWith('"')) {
      let body = v.slice(1);
      while (!closed(body) && i + 1 < lines.length) body += '\n' + lines[++i];
      v = unescape(body);
    } else if (v.startsWith("'")) {
      const j = v.indexOf("'", 1);
      v = j >= 0 ? v.slice(1, j) : v.slice(1);
    } else {
      const j = v.indexOf(' #');
      if (j >= 0) v = v.slice(0, j).trim();
    }
    out.push({ key, value: v });
  }
  return out;
}

/** Fingerprints of values worth matching against leaks (12+ characters). */
export async function fingerprints(text: string) {
  return Promise.all(parseEnv(text).filter((v) => v.value.length >= 12).map(async (v) => ({ name: v.key, sha256: await fingerprint(v.value) })));
}

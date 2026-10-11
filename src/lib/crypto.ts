// Uçtan uca şifreleme: ECDH P-256 + AES-GCM 256 (WebCrypto API)
// Özel anahtar asla sunucuya açık gitmez. Şifre ile AES-GCM ile sarılır.

export function bufToB64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function b64ToBuf(b64: string): Uint8Array<ArrayBuffer> {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function randSalt(len = 16): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(len));
}

async function passwordToKek(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: 150_000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function generateIdentity() {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveKey",
    "deriveBits",
  ]);
  const pubJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  return { keyPair, pubJwk, privJwk };
}

export async function lockPrivateKey(privJwk: JsonWebKey, password: string) {
  const salt = randSalt();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const kek = await passwordToKek(password, salt);
  const data = new TextEncoder().encode(JSON.stringify(privJwk));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, kek, data);
  return { encryptedPrivB64: bufToB64(ct), saltB64: bufToB64(salt), ivB64: bufToB64(iv) };
}

export async function unlockPrivateKey(
  encryptedPrivB64: string,
  saltB64: string,
  ivB64: string,
  password: string
): Promise<{ privJwk: JsonWebKey; privateKey: CryptoKey }> {
  const kek = await passwordToKek(password, b64ToBuf(saltB64));
  const ct = b64ToBuf(encryptedPrivB64);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(ivB64) as BufferSource },
    kek,
    ct as BufferSource
  );
  const privJwk = JSON.parse(new TextDecoder().decode(plain));
  const privateKey = await crypto.subtle.importKey("jwk", privJwk, { name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveKey",
  ]);
  return { privJwk, privateKey };
}

export async function importPeerPublicKey(pubJwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", pubJwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
}

export async function deriveRoomKey(myPrivateKey: CryptoKey, peerPublicKey: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: peerPublicKey },
    myPrivateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptText(roomKey: CryptoKey, plaintext: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    roomKey,
    new TextEncoder().encode(plaintext)
  );
  return { ivB64: bufToB64(iv), ctB64: bufToB64(ct) };
}

export async function decryptText(roomKey: CryptoKey, ivB64: string, ctB64: string) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(ivB64) as BufferSource },
    roomKey,
    b64ToBuf(ctB64) as BufferSource
  );
  return new TextDecoder().decode(plain);
}

// Resim/dosya için binary şifreleme (aynı oda anahtarı, AES-GCM)
export async function encryptBytes(roomKey: CryptoKey, data: Uint8Array) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, roomKey, data as BufferSource);
  return { ivB64: bufToB64(iv), ctB64: bufToB64(ct) };
}

export async function decryptBytes(roomKey: CryptoKey, ivB64: string, ctB64: string): Promise<Uint8Array<ArrayBuffer>> {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(ivB64) as BufferSource },
    roomKey,
    b64ToBuf(ctB64) as BufferSource
  );
  return new Uint8Array(plain);
}

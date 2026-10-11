// Kalıcı oturum: özel anahtar IndexedDB'de DIŞA AKTARILAMAZ modda tutulur.
// Sayfa yenilenince şifre sormadan devam edilir. "Çıkış" her şeyi siler.

export type SavedSession = {
  username: string;
  pubJwk: JsonWebKey;
  privateKey: CryptoKey; // extractable: false
};

const DB = "e2e-chat";
const STORE = "s";
const KEY = "session";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function saveSession(s: SavedSession): Promise<void> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(s, KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
  try {
    localStorage.setItem("e2e_remember", "1");
  } catch { /* gizli mod vs. */ }
}

export async function loadSession(): Promise<SavedSession | null> {
  try {
    if (localStorage.getItem("e2e_remember") !== "1") return null;
  } catch {
    return null;
  }
  try {
    const db = await openDb();
    const val: SavedSession | undefined = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get(KEY);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    db.close();
    if (!val?.username || !val.privateKey) return null;
    return val;
  } catch {
    return null;
  }
}

export async function clearSession(): Promise<void> {
  try {
    localStorage.removeItem("e2e_remember");
    localStorage.removeItem("e2e_session");
  } catch { /* yoksay */ }
  try {
    const db = await openDb();
    await new Promise<void>((resolve) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete(KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
    db.close();
  } catch { /* yoksay */ }
}

// JWK'tan dışa aktarılamaz anahtar üret (sadece bu cihazda kullanılabilir)
export async function toUnextractable(privJwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", privJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]);
}

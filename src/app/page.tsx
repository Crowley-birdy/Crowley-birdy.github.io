"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  generateIdentity,
  lockPrivateKey,
  unlockPrivateKey,
  importPeerPublicKey,
  deriveRoomKey,
  encryptText,
  decryptText,
} from "@/lib/crypto";
import { supabase, supabaseConfigured } from "@/lib/supabase";

type UserRec = { pubJwk: JsonWebKey; encryptedPrivB64: string; saltB64: string; ivB64: string };
type ServerMsg = { from: string; to: string; iv: string; ct: string; ts: number };
type ChatMsg = ServerMsg & { plain: string; mine: boolean };

const USERS_KEY = "e2e_users_v1";
const SERVER_KEY = "e2e_server_v1";

function loadUsers(): Record<string, UserRec> {
  try {
    return JSON.parse(localStorage.getItem(USERS_KEY) ?? "{}");
  } catch {
    return {};
  }
}
function loadServer(): ServerMsg[] {
  try {
    return JSON.parse(localStorage.getItem(SERVER_KEY) ?? "[]");
  } catch {
    return [];
  }
}

export default function Home() {
  const [tab, setTab] = useState<"auth" | "chat">("auth");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [me, setMe] = useState<string | null>(null);
  const [myPriv, setMyPriv] = useState<CryptoKey | null>(null);
  const [myPubJwk, setMyPubJwk] = useState<JsonWebKey | null>(null);
  const [peer, setPeer] = useState("");
  const [peerJwkText, setPeerJwkText] = useState("");
  const [roomKey, setRoomKey] = useState<CryptoKey | null>(null);
  const [draft, setDraft] = useState("");
  const [msgs, setMsgs] = useState<ChatMsg[]>([]);
  const [err, setErr] = useState("");
  const [info, setInfo] = useState("");
  const [showServer, setShowServer] = useState(true);

  // sekmeler arası senkron için ref'ler (storage event stale closure yemesin)
  const meRef = useRef<string | null>(null);
  meRef.current = me;
  const peerRef = useRef("");
  peerRef.current = peer;
  const roomKeyRef = useRef<CryptoKey | null>(null);
  roomKeyRef.current = roomKey;

  const serverMsgs = useMemo(() => loadServer(), [msgs, me]); // eslint-disable-line

  useEffect(() => {
    const s = localStorage.getItem("e2e_session");
    if (s) {
      // oturum sadece isim tutar, anahtar şifreyle açılır -> tekrar giriş ister
      setUsername(s);
      setTab("auth");
    }
  }, []);

  async function register() {
    setErr("");
    setInfo("");
    const u = username.trim().toLowerCase();
    if (u.length < 3) return setErr("Rumuz en az 3 harf olsun.");
    if (password.length < 4) return setErr("Şifre en az 4 karakter olsun.");
    const users = loadUsers();
    if (users[u]) return setErr("Bu rumuz zaten kayıtlı (bu cihazda). Giriş yap.");
    const { pubJwk, privJwk } = await generateIdentity();
    const locked = await lockPrivateKey(privJwk, password);
    users[u] = { pubJwk, ...locked };
    localStorage.setItem(USERS_KEY, JSON.stringify(users));

    if (supabaseConfigured && supabase) {
      await supabase.from("profiles").upsert({
        username: u,
        public_key: pubJwk,
        encrypted_priv: locked.encryptedPrivB64,
        salt: locked.saltB64,
        iv: locked.ivB64,
      });
    }
    setInfo("Kayıt tamam. Şimdi giriş yap.");
  }

  async function login() {
    setErr("");
    setInfo("");
    const u = username.trim().toLowerCase();
    let rec: UserRec | undefined = loadUsers()[u];
    // Cihazda yoksa Supabase'ten çek (başka cihazdan giriş)
    if (!rec && supabaseConfigured && supabase) {
      const { data } = await supabase.from("profiles").select("*").eq("username", u).single();
      if (data) {
        rec = {
          pubJwk: data.public_key,
          encryptedPrivB64: data.encrypted_priv,
          saltB64: data.salt,
          ivB64: data.iv,
        };
        const users = loadUsers();
        users[u] = rec;
        localStorage.setItem(USERS_KEY, JSON.stringify(users));
      }
    }
    if (!rec) return setErr("Kullanıcı bulunamadı. Önce kayıt ol.");
    try {
      const { privateKey } = await unlockPrivateKey(rec.encryptedPrivB64, rec.saltB64, rec.ivB64, password);
      setMe(u);
      setMyPriv(privateKey);
      setMyPubJwk(rec.pubJwk);
      localStorage.setItem("e2e_session", u);
      setTab("chat");
    } catch {
      setErr("Şifre yanlış (özel anahtar açılamadı).");
    }
  }

  async function connectPeer() {
    setErr("");
    setInfo("");
    if (!myPriv || !me) return;
    const p = peer.trim().toLowerCase();
    if (!p) return setErr("Önce karşı rumuzu yaz.");
    if (p === me) return setErr("Kendinle sohbet edemezsin :)");
    let peerJwk: JsonWebKey | null = null;
    if (peerJwkText.trim()) {
      try {
        peerJwk = JSON.parse(peerJwkText.trim());
      } catch {
        return setErr("Yapıştırılan açık anahtar JSON değil.");
      }
    } else {
      // önce yerelden, sonra Supabase'ten bul
      const local = loadUsers()[p];
      if (local) peerJwk = local.pubJwk;
      else if (supabaseConfigured && supabase) {
        const { data } = await supabase.from("profiles").select("public_key").eq("username", p).single();
        if (data) peerJwk = data.public_key;
      }
      if (!peerJwk) return setErr("Kişi bulunamadı. Karşı taraftan açık anahtarını isteyip aşağıdaki kutuya yapıştır.");
    }
    if (!peerJwk) return setErr("Açık anahtar eksik.");
    try {
      const peerPub = await importPeerPublicKey(peerJwk);
      const rk = await deriveRoomKey(myPriv, peerPub);
      setRoomKey(rk);
      setPeer(p);
      setInfo(`${p} ile güvenli kanal kuruldu. Sunucu sadece şifreli metin görecek.`);
      await refresh(p, rk);
    } catch {
      setErr("Kanal kurulamadı. Anahtar geçersiz.");
    }
  }

  async function refresh(forPeer?: string, rk?: CryptoKey) {
    const p = forPeer ?? peerRef.current;
    const key = rk ?? roomKeyRef.current;
    const myName = meRef.current;
    if (!myName || !p || !key) return;
    let all: ServerMsg[] = loadServer();
    if (supabaseConfigured && supabase) {
      const { data } = await supabase!
        .from("messages")
        .select("*")
        .or(`and(sender.eq.${myName},receiver.eq.${p}),and(sender.eq.${p},receiver.eq.${myName})`)
        .order("created_at", { ascending: true })
        .limit(100);
      if (data) {
        all = data.map((m: { sender: string; receiver: string; iv: string; ct: string; created_at: string }) => ({
          from: m.sender,
          to: m.receiver,
          iv: m.iv,
          ct: m.ct,
          ts: new Date(m.created_at).getTime(),
        }));
      }
    } else {
      all = all.filter((m) => (m.from === myName && m.to === p) || (m.from === p && m.to === myName));
    }
    const out: ChatMsg[] = [];
    for (const m of all) {
      try {
        const plain = await decryptText(key, m.iv, m.ct);
        out.push({ ...m, plain, mine: m.from === myName });
      } catch {
        out.push({ ...m, plain: "(çözülemedi)", mine: m.from === myName });
      }
    }
    // sadece gerçekten değiştiyse yaz (gereksiz render engelle)
    setMsgs((prev) => {
      if (prev.length === out.length && prev.every((v, i) => v.ct === out[i].ct && v.plain === out[i].plain)) return prev;
      return out;
    });
  }

  async function send() {
    setErr("");
    const myName = meRef.current;
    const p = peerRef.current;
    const key = roomKeyRef.current;
    if (!draft.trim() || !key || !myName || !p) return;
    const { ivB64, ctB64 } = await encryptText(key, draft.trim());
    const row: ServerMsg = { from: myName, to: p, iv: ivB64, ct: ctB64, ts: Date.now() };
    const all = loadServer();
    all.push(row);
    localStorage.setItem(SERVER_KEY, JSON.stringify(all));
    try {
      new BroadcastChannel(SERVER_KEY).postMessage("new");
    } catch { /* yoksa polling yakalar */ }
    if (supabaseConfigured && supabase) {
      await supabase!.from("messages").insert({ sender: myName, receiver: p, iv: ivB64, ct: ctB64 });
    }
    setDraft("");
    await refresh();
  }

  // Supabase realtime: yeni mesaj gelirse çözüp göster
  useEffect(() => {
    if (!supabaseConfigured || !supabase || !me || !peer || !roomKey) return;
    const sb = supabase!;
    const ch = sb
      .channel("msgs")
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "messages" }, () => refresh())
      .subscribe();
    return () => {
      sb.removeChannel(ch);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me, peer, roomKey]);

  // Demo modu sekmeler arası canlı senkron: storage event + BroadcastChannel + polling
  useEffect(() => {
    if (!me || !peer || !roomKey || supabaseConfigured) return;
    const onStorage = (e: StorageEvent) => {
      if (e.key === SERVER_KEY) refresh();
    };
    window.addEventListener("storage", onStorage);
    let bc: BroadcastChannel | null = null;
    try {
      bc = new BroadcastChannel(SERVER_KEY);
      bc.onmessage = () => refresh();
    } catch { /* desteklenmiyorsa polling yeter */ }
    const t = setInterval(() => refresh(), 1500);
    return () => {
      window.removeEventListener("storage", onStorage);
      bc?.close();
      clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me, peer, roomKey]);

  function logout() {
    setMe(null);
    setMyPriv(null);
    setRoomKey(null);
    setMsgs([]);
    setPeer("");
    localStorage.removeItem("e2e_session");
    setTab("auth");
  }

  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100 p-4 sm:p-8">
      <div className="max-w-3xl mx-auto space-y-4">
        <header className="flex items-center justify-between">
          <h1 className="text-xl font-bold">🔒 E2E Chat <span className="text-xs font-normal text-zinc-400">uçtan uca şifreli</span></h1>
          <div className="text-xs text-zinc-400">
            {supabaseConfigured ? "● Supabase bağlı" : "○ Demo modu (yerel sunucu simülasyonu)"}
          </div>
        </header>

        {tab === "auth" || !me ? (
          <section className="bg-zinc-900 rounded-2xl p-5 space-y-3 border border-zinc-800">
            <h2 className="font-semibold">Rumuz + şifre ile giriş</h2>
            <p className="text-sm text-zinc-400">
              Şifren sunucuya hiç gitmez. Özel anahtarın şifrenle şifrelenip saklanır. Sunucu sadece açık anahtar ve şifreli mesaj görür.
            </p>
            <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="rumuz (örn. ayse)"
              className="w-full bg-zinc-800 rounded-lg px-3 py-2 outline-none" />
            <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" placeholder="şifre"
              className="w-full bg-zinc-800 rounded-lg px-3 py-2 outline-none" />
            <div className="flex gap-2">
              <button onClick={register} className="flex-1 bg-zinc-700 hover:bg-zinc-600 rounded-lg py-2">Kayıt ol</button>
              <button onClick={login} className="flex-1 bg-emerald-600 hover:bg-emerald-500 rounded-lg py-2 font-semibold">Giriş</button>
            </div>
            {err && <p className="text-red-400 text-sm">{err}</p>}
            {info && <p className="text-emerald-400 text-sm">{info}</p>}
            <details className="text-xs text-zinc-400">
              <summary className="cursor-pointer">İki kişiyi aynı tarayıcıda nasıl denersin?</summary>
              <p className="mt-1">1. ayse olarak kayıt ol → giriş → açık anahtarını kopyala → çıkış. 2. mehmet olarak kayıt ol → giriş → kişi: ayse + ayse&apos;nin anahtarını yapıştır → bağlan. Mesaj gönder. Sonra ayse ile giriş yapıp tersini yap.</p>
            </details>
          </section>
        ) : (
          <>
            <section className="bg-zinc-900 rounded-2xl p-5 space-y-3 border border-zinc-800">
              <div className="flex items-center justify-between">
                <p>Merhaba <b>{me}</b> 👋</p>
                <button onClick={logout} className="text-xs text-zinc-400 underline">çıkış</button>
              </div>
              <div>
                <p className="text-xs text-zinc-400 mb-1">Benim açık anahtarım (arkadaşına gönder):</p>
                <pre className="text-[11px] bg-zinc-800 rounded-lg p-2 overflow-auto max-h-24">{JSON.stringify(myPubJwk)}</pre>
                <button onClick={() => myPubJwk && navigator.clipboard.writeText(JSON.stringify(myPubJwk))}
                  className="mt-1 text-xs bg-zinc-700 rounded px-2 py-1">kopyala</button>
              </div>
              <div className="flex gap-2">
                <input value={peer} onChange={(e) => setPeer(e.target.value)} placeholder="karşı rumuz (örn. mehmet)"
                  className="flex-1 bg-zinc-800 rounded-lg px-3 py-2 outline-none" />
                <button onClick={connectPeer} className="bg-emerald-600 rounded-lg px-4 py-2 font-semibold">Bağlan</button>
                <button onClick={() => refresh()} className="bg-zinc-700 rounded-lg px-3 py-2">↻</button>
              </div>
              <textarea value={peerJwkText} onChange={(e) => setPeerJwkText(e.target.value)}
                placeholder="(opsiyonel) karşı tarafın açık anahtar JSON'unu yapıştır — Supabase bağlı değilse gerekli"
                className="w-full bg-zinc-800 rounded-lg px-3 py-2 outline-none text-xs h-16" />
              {err && <p className="text-red-400 text-sm">{err}</p>}
              {info && <p className="text-emerald-400 text-sm">{info}</p>}
            </section>

            {roomKey && (
              <section className="bg-zinc-900 rounded-2xl p-5 space-y-3 border border-emerald-900">
                <h3 className="font-semibold text-emerald-300">💬 {peer} ile güvenli sohbet</h3>
                <div className="space-y-2 max-h-80 overflow-auto">
                  {msgs.length === 0 && <p className="text-sm text-zinc-500">Henüz mesaj yok. İlk şifreli mesajı gönder!</p>}
                  {msgs.map((m, i) => (
                    <div key={i} className={`max-w-[80%] rounded-xl px-3 py-2 text-sm ${m.mine ? "ml-auto bg-emerald-700" : "bg-zinc-700"}`}>
                      <p>{m.plain}</p>
                      <p className="text-[10px] opacity-60 mt-1">{m.from} • {new Date(m.ts).toLocaleTimeString()}</p>
                    </div>
                  ))}
                </div>
                <div className="flex gap-2">
                  <input value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => e.key === "Enter" && send()}
                    placeholder="şifreli mesaj yaz..." className="flex-1 bg-zinc-800 rounded-lg px-3 py-2 outline-none" />
                  <button onClick={send} className="bg-emerald-600 rounded-lg px-4 py-2 font-semibold">Gönder</button>
                </div>

                <div className="pt-2 border-t border-zinc-800">
                  <label className="text-xs flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={showServer} onChange={(e) => setShowServer(e.target.checked)} />
                    Sunucunun gördüğünü göster (sadece şifreli metin)
                  </label>
                  {showServer && (
                    <pre className="text-[11px] bg-black rounded-lg p-2 mt-2 overflow-auto max-h-40 text-zinc-400">
                      {JSON.stringify(serverMsgs.filter((m) => (m.from === me && m.to === peer) || (m.from === peer && m.to === me)), null, 1)}
                    </pre>
                  )}
                </div>
              </section>
            )}
          </>
        )}

        <footer className="text-xs text-zinc-500 leading-relaxed">
          Nasıl çalışıyor? Kayıtta ECDH P-256 kimlik anahtarı üretilir, özel anahtar şifrenle (PBKDF2 150k + AES-GCM) kilitlenir.
          Sohbette ECDH ile ortak oda anahtarı türetilir, her mesaj AES-GCM ile şifrelenir. Sunucu (yerel simülasyon veya Supabase) sadece iv + şifreli metin görür.
          Ücretsiz yayın: bu repo Vercel&apos;e + Supabase ücretsiz katmanına bağlanır. <code>supabase/schema.sql</code>&apos;i çalıştır, <code>.env.example</code>&apos;deki 2 anahtarı Vercel&apos;e ekle.
        </footer>
      </div>
    </main>
  );
}

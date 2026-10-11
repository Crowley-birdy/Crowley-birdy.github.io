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
  encryptBytes,
  decryptBytes,
  bufToB64,
  b64ToBuf,
} from "@/lib/crypto";
import { supabase, supabaseConfigured } from "@/lib/supabase";
import { saveSession, loadSession, clearSession, toUnextractable } from "@/lib/session";

type UserRec = { pubJwk: JsonWebKey; encryptedPrivB64: string; saltB64: string; ivB64: string };
type ServerMsg = { from: string; to: string; iv: string; ct: string; ts: number; kind: string };
type ReplyRef = { from: string; snippet: string };
type ChatMsg = ServerMsg & { plain: string; mine: boolean; reply?: ReplyRef };
// Şifreli zarf: yanıt alıntısı da şifrenin İÇİNDE taşınır (sunucu göremez)
type Envelope = { v: 1; kind: string; body: string; biv?: string; reply?: ReplyRef };

const EMOJIS = ["😀","😁","😂","🤣","😊","😍","😘","😎","🤔","😐","🙄","😴","😷","🤒","😢","😭","😡","🤯","🥳","😇","🙏","👍","👎","👏","🙌","🤝","✌️","🤞","👀","🧠","❤️","💔","💯","🔥","🎉","⭐","🌙","☀️","🌈","⚡","🎬","📷","🎵","⚽","🚀","🍕","☕","🌹","🐱","🐶"];

async function decodeRow(key: CryptoKey, m: ServerMsg): Promise<{ kind: string; body: string; reply?: ReplyRef; biv?: string }> {
  if (m.kind === "video") {
    const p = JSON.parse(await decryptText(key, m.iv, m.ct)) as Envelope;
    return { kind: "video", body: p.body, reply: p.reply, biv: p.biv };
  }
  if (m.kind === "image") {
    try {
      const p = JSON.parse(await decryptText(key, m.iv, m.ct)) as Envelope;
      if (p && p.v === 1) return { kind: p.kind ?? "image", body: p.body, reply: p.reply };
    } catch { /* eski format: ham şifreli jpeg */ }
    return { kind: "image", body: bufToB64(await decryptBytes(key, m.iv, m.ct)) };
  }
  const t = await decryptText(key, m.iv, m.ct);
  try {
    const p = JSON.parse(t) as Envelope;
    if (p && p.v === 1) return { kind: "text", body: p.body, reply: p.reply };
  } catch { /* eski düz metin */ }
  return { kind: "text", body: t };
}

const USERS_KEY = "e2e_users_v1";
const SERVER_KEY = "e2e_server_v1";
const CONTACTS_KEY = "e2e_contacts_v1";

type Contact = { name: string; pubJwk?: JsonWebKey; addedAt: number };

function loadContacts(me: string): Contact[] {
  try {
    const all = JSON.parse(localStorage.getItem(CONTACTS_KEY) ?? "{}");
    return all[me] ?? [];
  } catch {
    return [];
  }
}
function saveContact(me: string, c: Contact) {
  try {
    const all = JSON.parse(localStorage.getItem(CONTACTS_KEY) ?? "{}");
    const list: Contact[] = all[me] ?? [];
    const i = list.findIndex((x) => x.name === c.name);
    if (i >= 0) list[i] = { ...list[i], ...c };
    else list.push(c);
    all[me] = list;
    localStorage.setItem(CONTACTS_KEY, JSON.stringify(all));
  } catch { /* yoksay */ }
  return loadContacts(me);
}
function removeContact(me: string, name: string) {
  try {
    const all = JSON.parse(localStorage.getItem(CONTACTS_KEY) ?? "{}");
    all[me] = ((all[me] ?? []) as Contact[]).filter((x) => x.name !== name);
    localStorage.setItem(CONTACTS_KEY, JSON.stringify(all));
  } catch { /* yoksay */ }
  return loadContacts(me);
}

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
  const [remember, setRemember] = useState(true);
  const [booting, setBooting] = useState(true);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [reply, setReply] = useState<ReplyRef | null>(null);
  const [showEmoji, setShowEmoji] = useState(false);
  const [sending, setSending] = useState(false);

  // sekmeler arası senkron için ref'ler (storage event stale closure yemesin)
  const meRef = useRef<string | null>(null);
  meRef.current = me;
  const peerRef = useRef("");
  peerRef.current = peer;
  const roomKeyRef = useRef<CryptoKey | null>(null);
  roomKeyRef.current = roomKey;

  // giriş yapanın kişi listesini yükle
  useEffect(() => {
    if (me) setContacts(loadContacts(me));
    else setContacts([]);
  }, [me]);

  const serverMsgs = useMemo(() => loadServer(), [msgs, me]); // eslint-disable-line

  useEffect(() => {
    (async () => {
      try {
        const s = await loadSession();
        if (s) {
          setMe(s.username);
          setMyPriv(s.privateKey);
          setMyPubJwk(s.pubJwk);
          setUsername(s.username);
          setTab("chat");
          setBooting(false);
          return;
        }
      } catch { /* düşerse normal girişe in */ }
      try {
        const name = localStorage.getItem("e2e_session");
        if (name) setUsername(name);
      } catch { /* yoksay */ }
      setTab("auth");
      setBooting(false);
    })();
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
      const { privJwk, privateKey } = await unlockPrivateKey(rec.encryptedPrivB64, rec.saltB64, rec.ivB64, password);
      setMe(u);
      setMyPriv(privateKey);
      setMyPubJwk(rec.pubJwk);
      try {
        localStorage.setItem("e2e_session", u);
      } catch { /* yoksay */ }
      if (remember) {
        try {
          // şifre bir daha sorulmasın: anahtarı dışa aktarılamaz modda kasaya koy
          await saveSession({ username: u, pubJwk: rec.pubJwk, privateKey: await toUnextractable(privJwk) });
        } catch { /* kasa yazılamazsa normal devam */ }
      } else {
        await clearSession();
      }
      setPassword("");
      setTab("chat");
    } catch {
      setErr("Şifre yanlış (özel anahtar açılamadı).");
    }
  }

  async function connectPeer(target?: string) {
    setErr("");
    setInfo("");
    if (!myPriv || !me) return;
    const myName = meRef.current!;
    const p = (target ?? peer).trim().toLowerCase();
    if (!p) return setErr("Önce karşı rumuzu yaz.");
    if (p === myName) return setErr("Kendinle sohbet edemezsin :)");
    let peerJwk: JsonWebKey | null = null;
    if (!target && peerJwkText.trim()) {
      try {
        peerJwk = JSON.parse(peerJwkText.trim());
      } catch {
        return setErr("Yapıştırılan açık anahtar JSON değil.");
      }
    } else {
      // önce kayıtlı kişiler, sonra bu cihaz, sonra Supabase
      const saved = loadContacts(myName).find((c) => c.name === p);
      if (saved?.pubJwk) peerJwk = saved.pubJwk;
      if (!peerJwk) {
        const local = loadUsers()[p];
        if (local) peerJwk = local.pubJwk;
      }
      if (!peerJwk && supabaseConfigured && supabase) {
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
      setContacts(saveContact(myName, { name: p, pubJwk: peerJwk, addedAt: Date.now() }));
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
        all = data.map((m: { sender: string; receiver: string; iv: string; ct: string; created_at: string; kind?: string }) => ({
          from: m.sender,
          to: m.receiver,
          iv: m.iv,
          ct: m.ct,
          kind: m.kind ?? "text",
          ts: new Date(m.created_at).getTime(),
        }));
      }
    } else {
      all = all
        .filter((m) => (m.from === myName && m.to === p) || (m.from === p && m.to === myName))
        .map((m) => ({ ...m, kind: (m as ServerMsg).kind ?? "text" }));
    }
    const out: ChatMsg[] = [];
    for (const m of all) {
      try {
        const d = await decodeRow(key, m);
        if (d.kind === "image") {
          out.push({ ...m, kind: "image", plain: "data:image/jpeg;base64," + d.body, mine: m.from === myName, reply: d.reply });
        } else if (d.kind === "video") {
          let url = "";
          if (supabaseConfigured && supabase && d.biv) {
            try {
              const { data } = supabase!.storage.from("chat-media").getPublicUrl(d.body);
              const res = await fetch(data.publicUrl);
              if (res.ok) {
                const encB64 = bufToB64(new Uint8Array(await res.arrayBuffer()));
                const raw = await decryptBytes(key, d.biv, encB64);
                url = URL.createObjectURL(new Blob([raw as unknown as BlobPart], { type: "video/mp4" }));
              }
            } catch { /* aşağıda "(alınamadı)" olur */ }
          }
          out.push({ ...m, kind: "video", plain: url, mine: m.from === myName, reply: d.reply });
        } else {
          out.push({ ...m, kind: "text", plain: d.body, mine: m.from === myName, reply: d.reply });
        }
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

  function snippetOf(m: ChatMsg): string {
    if (m.kind === "image") return "📷 resim";
    if (m.kind === "video") return "🎬 video";
    return m.plain.length > 80 ? m.plain.slice(0, 80) + "…" : m.plain;
  }

  // Şifreli satırı yayınla: yerelde + Supabase'te (sunucu hep şifreli görür)
  async function publish(kind: string, ivB64: string, ctB64: string) {
    const myName = meRef.current!;
    const p = peerRef.current;
    const row: ServerMsg = { from: myName, to: p, iv: ivB64, ct: ctB64, ts: Date.now(), kind };
    const all = loadServer();
    all.push(row);
    try {
      localStorage.setItem(SERVER_KEY, JSON.stringify(all));
    } catch {
      if (!supabaseConfigured) throw new Error("depo-dolu");
    }
    try {
      new BroadcastChannel(SERVER_KEY).postMessage("new");
    } catch { /* yoksa polling yakalar */ }
    if (supabaseConfigured && supabase) {
      const { error } = await supabase!.from("messages").insert({ sender: myName, receiver: p, iv: ivB64, ct: ctB64, kind });
      if (error) throw new Error(error.message);
    }
    await refresh();
  }

  function envelope(kind: string, body: string, extra?: Partial<Envelope>): Envelope {
    return { v: 1, kind, body, ...extra, reply: reply ?? undefined };
  }

  async function send() {
    setErr("");
    const myName = meRef.current;
    const p = peerRef.current;
    const key = roomKeyRef.current;
    if (!draft.trim() || !key || !myName || !p || sending) return;
    try {
      const { ivB64, ctB64 } = await encryptText(key, JSON.stringify(envelope("text", draft.trim())));
      await publish("text", ivB64, ctB64);
      setDraft("");
      setReply(null);
    } catch (e) {
      setErr(e instanceof Error && e.message === "depo-dolu" ? "Tarayıcı deposu doldu." : "Gönderilemedi.");
    }
  }

  // Resmi küçültüp JPEG'e çevir (şifreli yükü küçük tutar, max ~1024px)
  async function compressImage(file: File): Promise<Uint8Array> {
    const bmp = await createImageBitmap(file);
    const scale = Math.min(1, 1024 / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * scale));
    const h = Math.max(1, Math.round(bmp.height * scale));
    const canvas = document.createElement("canvas");
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext("2d")!;
    ctx.drawImage(bmp, 0, 0, w, h);
    bmp.close();
    const blob: Blob | null = await new Promise((res) => canvas.toBlob(res, "image/jpeg", 0.72));
    if (!blob) throw new Error("resim işlenemedi");
    return new Uint8Array(await blob.arrayBuffer());
  }

  async function sendImage(file: File) {
    setErr("");
    setInfo("");
    const key = roomKeyRef.current;
    if (!key || !meRef.current || !peerRef.current || sending) return;
    if (!file.type.startsWith("image/")) return setErr("Sadece resim dosyası gönderebilirsin.");
    setSending(true);
    try {
      setInfo("Resim şifreleniyor...");
      const bytes = await compressImage(file);
      if (bytes.length > 900 * 1024) {
        setErr("Resim hâlâ çok büyük, daha küçük bir resim dene.");
        setInfo("");
        return;
      }
      const payload = JSON.stringify(envelope("image", bufToB64(bytes)));
      const { ivB64, ctB64 } = await encryptText(key, payload);
      await publish("image", ivB64, ctB64);
      setReply(null);
      setInfo("");
    } catch (e) {
      setErr(e instanceof Error && e.message === "depo-dolu" ? "Tarayıcı deposu doldu (demo modu limiti)." : e instanceof Error ? "Gönderilemedi: " + e.message : "Resim gönderilemedi.");
      setInfo("");
    } finally {
      setSending(false);
    }
  }

  async function sendVideo(file: File) {
    setErr("");
    setInfo("");
    const key = roomKeyRef.current;
    if (!key || !meRef.current || !peerRef.current || sending) return;
    if (!supabaseConfigured || !supabase) return setErr("Video için Supabase bağlantısı gerekli (demo modunda yok).");
    if (!file.type.startsWith("video/")) return setErr("Sadece video dosyası seçebilirsin.");
    if (file.size > 25 * 1024 * 1024) return setErr("Video 25MB'tan büyük olamaz (ücretsiz kota).");
    setSending(true);
    try {
      setInfo("Video şifrelenip yükleniyor...");
      const bytes = new Uint8Array(await file.arrayBuffer());
      const { ivB64, ctB64 } = await encryptBytes(key, bytes);
      const path = `${meRef.current}/${Date.now()}-${Math.random().toString(36).slice(2)}.enc`;
      const { error: upErr } = await supabase!.storage
        .from("chat-media")
        .upload(path, new Blob([b64ToBuf(ctB64)], { type: "application/octet-stream" }));
      if (upErr) {
        setErr("Yüklenemedi: " + upErr.message);
        setInfo("");
        return;
      }
      const payload = JSON.stringify(envelope("video", path, { biv: ivB64 }));
      const e2 = await encryptText(key, payload);
      await publish("video", e2.ivB64, e2.ctB64);
      setReply(null);
      setInfo("");
    } catch (e) {
      setErr(e instanceof Error ? "Gönderilemedi: " + e.message : "Video gönderilemedi.");
      setInfo("");
    } finally {
      setSending(false);
    }
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

  async function logout() {
    setMe(null);
    setMyPriv(null);
    setRoomKey(null);
    setMsgs([]);
    setPeer("");
    await clearSession();
    setTab("auth");
  }

  if (booting) {
    return (
      <main className="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center">
        <p className="text-sm text-zinc-400">🔒 Oturum açılıyor...</p>
      </main>
    );
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
            <label className="text-sm flex items-center gap-2 cursor-pointer text-zinc-300">
              <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
              Oturumu açık tut (bu cihazda şifre sorma)
            </label>
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
                <button onClick={() => connectPeer()} className="bg-emerald-600 rounded-lg px-4 py-2 font-semibold">Bağlan</button>
                <button onClick={() => refresh()} className="bg-zinc-700 rounded-lg px-3 py-2">↻</button>
              </div>
              <textarea value={peerJwkText} onChange={(e) => setPeerJwkText(e.target.value)}
                placeholder="(opsiyonel) karşı tarafın açık anahtar JSON'unu yapıştır — Supabase bağlı değilse gerekli"
                className="w-full bg-zinc-800 rounded-lg px-3 py-2 outline-none text-xs h-16" />
              {contacts.length > 0 && (
                <div>
                  <p className="text-xs text-zinc-400 mb-1">Kişiler (tek tıkla sohbet):</p>
                  <div className="flex flex-wrap gap-2">
                    {contacts.map((c) => (
                      <span key={c.name} className={`flex items-center gap-1 rounded-full pl-3 pr-1 py-1 text-sm ${peer === c.name && roomKey ? "bg-emerald-700" : "bg-zinc-800"}`}>
                        <button onClick={() => connectPeer(c.name)} className="font-medium">💬 {c.name}</button>
                        <button
                          title={`${c.name} kişisini sil`}
                          onClick={() => me && setContacts(removeContact(me, c.name))}
                          className="text-zinc-500 hover:text-red-400 rounded-full px-1"
                        >×</button>
                      </span>
                    ))}
                  </div>
                </div>
              )}
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
                      {m.reply && (
                        <div className="text-xs opacity-80 border-l-2 border-white/40 pl-2 mb-1">
                          <span className="font-semibold">{m.reply.from}:</span> {m.reply.snippet}
                        </div>
                      )}
                      {m.kind === "image" ? (
                        // eslint-disable-next-line @next/next/no-img-element
                        <img src={m.plain} alt="şifreli resim" className="rounded-lg max-w-full" />
                      ) : m.kind === "video" ? (
                        m.plain ? (
                          <video src={m.plain} controls preload="metadata" className="rounded-lg max-w-full" />
                        ) : (
                          <p className="italic opacity-70">(video alınamadı)</p>
                        )
                      ) : (
                        <p>{m.plain}</p>
                      )}
                      <p className="text-[10px] opacity-60 mt-1 flex items-center gap-2">
                        <span>{m.from} • {new Date(m.ts).toLocaleTimeString()}</span>
                        <button title="Yanıtla" onClick={() => setReply({ from: m.from, snippet: snippetOf(m) })} className="hover:opacity-100 opacity-70">↩</button>
                      </p>
                    </div>
                  ))}
                </div>
                {reply && (
                  <div className="flex items-center gap-2 text-xs bg-zinc-800 rounded-lg px-3 py-2">
                    <span className="flex-1 truncate"><b>{reply.from}:</b> {reply.snippet}</span>
                    <button onClick={() => setReply(null)} className="text-zinc-400 hover:text-white">✕</button>
                  </div>
                )}
                <div className="flex gap-2 relative">
                  <input value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => e.key === "Enter" && send()}
                    placeholder="şifreli mesaj yaz..." className="flex-1 bg-zinc-800 rounded-lg px-3 py-2 outline-none" />
                  <button onClick={() => setShowEmoji((v) => !v)} title="Emoji" className="bg-zinc-700 hover:bg-zinc-600 rounded-lg px-3 py-2">😊</button>
                  <label className="bg-zinc-700 hover:bg-zinc-600 rounded-lg px-3 py-2 cursor-pointer" title="Şifreli resim gönder">
                    📷
                    <input type="file" accept="image/*" className="hidden" onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) sendImage(f);
                      e.target.value = "";
                    }} />
                  </label>
                  <label className="bg-zinc-700 hover:bg-zinc-600 rounded-lg px-3 py-2 cursor-pointer" title="Şifreli video gönder (max 25MB)">
                    🎬
                    <input type="file" accept="video/*" className="hidden" onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) sendVideo(f);
                      e.target.value = "";
                    }} />
                  </label>
                  <button onClick={send} disabled={sending} className="bg-emerald-600 rounded-lg px-4 py-2 font-semibold disabled:opacity-50">
                    {sending ? "…" : "Gönder"}
                  </button>
                  {showEmoji && (
                    <div className="absolute bottom-12 right-0 bg-zinc-800 border border-zinc-700 rounded-xl p-2 grid grid-cols-8 gap-1 max-w-[280px] z-10">
                      {EMOJIS.map((e) => (
                        <button key={e} onClick={() => setDraft((d) => d + e)} className="text-xl hover:bg-zinc-700 rounded p-0.5">{e}</button>
                      ))}
                    </div>
                  )}
                </div>

                <div className="pt-2 border-t border-zinc-800">
                  <label className="text-xs flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={showServer} onChange={(e) => setShowServer(e.target.checked)} />
                    Sunucunun gördüğünü göster (sadece şifreli metin)
                  </label>
                  {showServer && (
                    <pre className="text-[11px] bg-black rounded-lg p-2 mt-2 overflow-auto max-h-40 text-zinc-400">
                      {JSON.stringify(serverMsgs.filter((m) => (m.from === me && m.to === peer) || (m.from === peer && m.to === me)), (k, v) => typeof v === "string" && v.length > 120 ? v.slice(0, 120) + `…(${v.length} karakter)` : v, 1)}
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

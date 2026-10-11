"use client";
import { useEffect, useRef, useState } from "react";
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

type ThemeId = "dark" | "gruvbox" | "dracula" | "nord" | "light" | "custom";
const THEMES: { id: ThemeId; name: string; dots: [string, string, string] }[] = [
  { id: "dark", name: "Gece", dots: ["#09090b", "#27272a", "#059669"] },
  { id: "gruvbox", name: "Gruvbox", dots: ["#282828", "#504945", "#b8bb26"] },
  { id: "dracula", name: "Dracula", dots: ["#282a36", "#44475a", "#50fa7b"] },
  { id: "nord", name: "Nord", dots: ["#2e3440", "#434c5e", "#88c0d0"] },
  { id: "light", name: "Açık", dots: ["#f1f1f4", "#ffffff", "#059669"] },
  { id: "custom", name: "Özel", dots: ["#888888", "#aaaaaa", "#cc6633"] },
];
const DEFAULT_CUSTOM = { bg: "#1c1917", panel: "#292524", accent: "#d6a35c", ink: "#f5f0e8" };

function hexLum(hex: string): number {
  const h = hex.replace("#", "");
  const v = (i: number) => parseInt(h.slice(i, i + 2), 16) / 255;
  const [r, g, b] = [v(0), v(2), v(4)];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

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
const OUTBOX_KEY = "e2e_outbox_v1";

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
  const [mobileTab, setMobileTab] = useState<"people" | "chat">("people");
  const [remember, setRemember] = useState(true);
  const [booting, setBooting] = useState(true);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [reply, setReply] = useState<ReplyRef | null>(null);
  const [showEmoji, setShowEmoji] = useState(false);
  const [showAttach, setShowAttach] = useState(false);
  const [sending, setSending] = useState(false);
  const [unread, setUnread] = useState<Record<string, number>>({});
  const [notifPerm, setNotifPerm] = useState<NotificationPermission>("default");
  const [muted, setMuted] = useState(false);
  const [connDown, setConnDown] = useState(false);
  const [theme, setTheme] = useState<ThemeId>("dark");
  const [custom, setCustom] = useState(DEFAULT_CUSTOM);
  const [showSettings, setShowSettings] = useState(false);

  // sekmeler arası senkron için ref'ler (storage event stale closure yemesin)
  const meRef = useRef<string | null>(null);
  meRef.current = me;
  const peerRef = useRef("");
  peerRef.current = peer;
  const roomKeyRef = useRef<CryptoKey | null>(null);
  roomKeyRef.current = roomKey;
  const myPrivRef = useRef<CryptoKey | null>(null);
  myPrivRef.current = myPriv;
  // bildirimler için: kişi -> oda anahtarı önbelleği, görülen son zamanlar
  const keyCacheRef = useRef<Record<string, CryptoKey>>({});
  const seenRef = useRef<Record<string, number>>({});
  const baseSetRef = useRef(false);
  const lastSendRef = useRef({ t: "", at: 0 });
  // çözülmüş mesaj önbelleği (ct -> ChatMsg): her yenilemede her şeyi baştan çözme
  const msgCache = useRef(new Map<string, ChatMsg>());
  function cachePut(ct: string, m: ChatMsg) {
    msgCache.current.set(ct, m);
    if (msgCache.current.size > 200) {
      const first = msgCache.current.keys().next().value;
      if (first !== undefined) msgCache.current.delete(first);
    }
  }
  const notifRef = useRef<NotificationPermission>("default");
  const mutedRef = useRef(false);

  // giriş yapanın kişi listesini yükle
  useEffect(() => {
    if (me) setContacts(loadContacts(me));
    else setContacts([]);
    keyCacheRef.current = {};
    seenRef.current = {};
    baseSetRef.current = false;
    msgCache.current.clear();
    setUnread({});
  }, [me]);

  useEffect(() => {
    mutedRef.current = muted;
  }, [muted]);

  // Tema: açılışta yükle + değişince uygula ve sakla
  useEffect(() => {
    try {
      const t = localStorage.getItem("e2e_theme") as ThemeId | null;
      if (t && THEMES.some((x) => x.id === t)) setTheme(t);
      const c = localStorage.getItem("e2e_custom");
      if (c) setCustom({ ...DEFAULT_CUSTOM, ...JSON.parse(c) });
    } catch { /* varsayılan tema */ }
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = theme;
    for (const p of ["--bg", "--panel", "--accent", "--ink", "--accent-ink", "--out", "--out-ink"]) {
      root.style.removeProperty(p);
    }
    if (theme === "custom") {
      root.style.setProperty("--bg", custom.bg);
      root.style.setProperty("--panel", custom.panel);
      root.style.setProperty("--accent", custom.accent);
      root.style.setProperty("--ink", custom.ink);
      const ink = hexLum(custom.accent) > 0.45 ? "#1a1a1a" : "#ffffff";
      root.style.setProperty("--accent-ink", ink);
      root.style.setProperty("--out", custom.accent);
      root.style.setProperty("--out-ink", ink);
    }
    try {
      localStorage.setItem("e2e_theme", theme);
      localStorage.setItem("e2e_custom", JSON.stringify(custom));
    } catch { /* gizli mod */ }
  }, [theme, custom]);

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
      setMobileTab("chat");
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
      try {
        // EN YENİ 100 mesaj (tersten çekip sırala; yoksa yeni mesajlar ekrana gelmez!)
        const { data, error } = await supabase!
          .from("messages")
          .select("*")
          .or(`and(sender.eq.${myName},receiver.eq.${p}),and(sender.eq.${p},receiver.eq.${myName})`)
          .order("created_at", { ascending: false })
          .limit(100);
        if (error) throw error;
        markConn(true);
        if (data) {
          all = data.reverse().map((m: { sender: string; receiver: string; iv: string; ct: string; created_at: string; kind?: string }) => ({
            from: m.sender,
            to: m.receiver,
            iv: m.iv,
            ct: m.ct,
            kind: m.kind ?? "text",
            ts: new Date(m.created_at).getTime(),
          }));
        }
      } catch {
        markConn(false);
        return; // eski mesajlar ekranda kalır, yenileme sonraki tura
      }
    } else {
      markConn(true);
      all = all
        .filter((m) => (m.from === myName && m.to === p) || (m.from === p && m.to === myName))
        .map((m) => ({ ...m, kind: (m as ServerMsg).kind ?? "text" }));
    }
    const out: ChatMsg[] = [];
    for (const m of all) {
      const mKind = m.kind ?? "text";
      const hit = msgCache.current.get(m.ct);
      if (hit && hit.kind === mKind) {
        out.push(hit.mine === (m.from === myName) ? hit : { ...hit, mine: m.from === myName });
        continue; // önbellek: indirme/çözme yok, anında
      }
      try {
        const d = await decodeRow(key, { ...m, kind: mKind });
        let entry: ChatMsg;
        if (d.kind === "image") {
          entry = { ...m, kind: "image", plain: "data:image/jpeg;base64," + d.body, mine: m.from === myName, reply: d.reply };
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
          entry = { ...m, kind: "video", plain: url, mine: m.from === myName, reply: d.reply };
        } else {
          entry = { ...m, kind: "text", plain: d.body, mine: m.from === myName, reply: d.reply };
        }
        cachePut(m.ct, entry);
        out.push(entry);
      } catch {
        out.push({ ...m, kind: mKind, plain: "(çözülemedi)", mine: m.from === myName });
      }
    }
    // sadece gerçekten değiştiyse yaz (gereksiz render engelle)
    setMsgs((prev) => {
      if (prev.length === out.length && prev.every((v, i) => v.ct === out[i].ct && v.plain === out[i].plain)) return prev;
      return out;
    });
    // bu sohbet ekranda: okundu say
    seenRef.current[p] = out.reduce((a, m) => Math.max(a, m.ts), seenRef.current[p] ?? 0);
    setUnread((u) => (u[p] ? { ...u, [p]: 0 } : u));
  }

  // Yeni mesaj avcısı: gelen kutusunu yoklar, rozet + ses + bildirim çıkarır
  useEffect(() => {
    if (!me || !myPriv) return;
    try {
      notifRef.current = Notification.permission;
      setNotifPerm(Notification.permission);
    } catch { /* desteklenmiyor */ }
    let stop = false;
    const tick = async () => {
      const myName = meRef.current;
      if (!myName || stop) return;
      try {
        // kuyrukta bekleyen giden mesajları dene
        try {
          if (await flushOutbox()) await refresh();
        } catch { /* sonraki tur */ }
        let incoming: { from: string; iv: string; ct: string; kind: string; ts: number }[] = [];
        if (supabaseConfigured && supabase) {
          const { data } = await supabase!
            .from("messages")
            .select("sender,iv,ct,kind,created_at")
            .eq("receiver", myName)
            .order("created_at", { ascending: false })
            .limit(30);
          if (data) {
            incoming = data.map((m: { sender: string; iv: string; ct: string; kind?: string; created_at: string }) => ({
              from: m.sender,
              iv: m.iv,
              ct: m.ct,
              kind: m.kind ?? "text",
              ts: new Date(m.created_at).getTime(),
            }));
          }
        } else {
          incoming = loadServer()
            .filter((m) => m.to === myName)
            .map((m) => ({ from: m.from, iv: m.iv, ct: m.ct, kind: (m as ServerMsg).kind ?? "text", ts: m.ts }));
        }
        // eskiden yeniye işle
        for (const m of incoming.reverse()) {
          if ((seenRef.current[m.from] ?? 0) >= m.ts) continue;
          seenRef.current[m.from] = m.ts;
          if (m.from === myName) continue;
          if (!baseSetRef.current) continue; // ilk tur: sessizce tabanı işaretle
          const viewing = m.from === peerRef.current && !document.hidden;
          const key = await roomKeyFor(m.from);
          let snippet = "Yeni mesaj";
          if (key) {
            try {
              const d = await decodeRow(key, { from: m.from, to: myName, iv: m.iv, ct: m.ct, ts: m.ts, kind: m.kind });
              snippet = d.kind === "image" ? "📷 resim gönderdi" : d.kind === "video" ? "🎬 video gönderdi" : d.body.slice(0, 100);
            } catch { /* özet çıkmazsa genel metin */ }
          }
          if (!viewing) {
            setUnread((u) => ({ ...u, [m.from]: (u[m.from] ?? 0) + 1 }));
            beep();
            notifyUser(m.from, snippet);
          }
        }
        baseSetRef.current = true;
      } catch { /* ağ hatasında sessiz geç, sonraki tur dener */ }
    };
    baseSetRef.current = false;
    const t = setInterval(tick, 5000);
    void tick();
    return () => {
      stop = true;
      clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me, myPriv]);

  // Sekme başlığında okunmadı sayacı
  const unreadTotal = Object.values(unread).reduce((a, b) => a + b, 0);
  useEffect(() => {
    document.title = unreadTotal > 0 ? `(${unreadTotal}) E2E Chat` : "E2E Chat";
  }, [unreadTotal]);

  function snippetOf(m: ChatMsg): string {
    if (m.kind === "image") return "📷 resim";
    if (m.kind === "video") return "🎬 video";
    return m.plain.length > 80 ? m.plain.slice(0, 80) + "…" : m.plain;
  }

  // Şifreli satırı yayınla: yerelde + Supabase'te (sunucu hep şifreli görür)
  // Dönüş: true = sunucuya yazıldı, false = kuyruğa alındı (bağlantı yok)
  function markConn(ok: boolean) {
    setConnDown((prev) => {
      const next = !ok;
      return prev === next ? prev : next;
    });
  }

  function stashOutbox(row: ServerMsg) {
    try {
      const box: ServerMsg[] = JSON.parse(localStorage.getItem(OUTBOX_KEY) ?? "[]");
      box.push(row);
      localStorage.setItem(OUTBOX_KEY, JSON.stringify(box.slice(-50))); // taşmayı önle
    } catch { /* yoksay */ }
  }

  async function flushOutbox(): Promise<boolean> {
    if (!supabaseConfigured || !supabase) return false;
    let box: ServerMsg[] = [];
    try {
      box = JSON.parse(localStorage.getItem(OUTBOX_KEY) ?? "[]");
    } catch {
      return false;
    }
    if (!box.length) return false;
    const rest: ServerMsg[] = [];
    for (const r of box) {
      try {
        const { error } = await supabase!.from("messages").insert({
          sender: r.from, receiver: r.to, iv: r.iv, ct: r.ct, kind: r.kind ?? "text",
        });
        if (error) rest.push(r);
      } catch {
        rest.push(r); // ağ hâlâ kopuk: kalanı sonraki tura
        break;
      }
    }
    try {
      localStorage.setItem(OUTBOX_KEY, JSON.stringify(rest));
    } catch { /* yoksay */ }
    return rest.length < box.length;
  }

  async function publish(kind: string, ivB64: string, ctB64: string): Promise<boolean> {
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
      try {
        const { error } = await supabase!.from("messages").insert({ sender: myName, receiver: p, iv: ivB64, ct: ctB64, kind });
        if (error) throw error;
        markConn(true);
      } catch {
        // bağlantı yok: kuyruğa al, bağlantı dönünce gidecek
        stashOutbox({ from: myName, to: p, iv: ivB64, ct: ctB64, ts: Date.now(), kind });
        markConn(false);
        return false;
      }
    }
    try {
      await refresh();
    } catch { /* yenileme patlarsa iyimser mesaj ekranda kalır */ }
    return true;
  }

  function envelope(kind: string, body: string, extra?: Partial<Envelope>): Envelope {
    return { v: 1, kind, body, ...extra, reply: reply ?? undefined };
  }

  // Bildirim için: bir gönderenin oda anahtarını bul (önbellekli)
  async function roomKeyFor(name: string): Promise<CryptoKey | null> {
    if (keyCacheRef.current[name]) return keyCacheRef.current[name];
    const priv = myPrivRef.current;
    if (!priv) return null;
    let jwk: JsonWebKey | null = loadContacts(meRef.current ?? "").find((c) => c.name === name)?.pubJwk ?? null;
    if (!jwk) jwk = loadUsers()[name]?.pubJwk ?? null;
    if (!jwk && supabaseConfigured && supabase) {
      const { data } = await supabase.from("profiles").select("public_key").eq("username", name).single();
      if (data?.public_key) jwk = data.public_key;
    }
    if (!jwk) return null;
    try {
      const k = await deriveRoomKey(priv, await importPeerPublicKey(jwk));
      keyCacheRef.current[name] = k;
      return k;
    } catch {
      return null;
    }
  }

  function beep() {
    if (mutedRef.current) return;
    try {
      const Ctx = window.AudioContext ?? (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      const ctx = new Ctx();
      const o = ctx.createOscillator();
      const g = ctx.createGain();
      o.connect(g);
      g.connect(ctx.destination);
      o.frequency.value = 880;
      g.gain.value = 0.07;
      o.start();
      o.stop(ctx.currentTime + 0.15);
      o.onended = () => void ctx.close();
    } catch { /* sessiz devam */ }
  }

  function notifyUser(from: string, snippet: string) {
    if (notifRef.current !== "granted") return;
    try {
      const n = new Notification(`💬 ${from}`, { body: snippet, tag: `e2e-${from}` });
      n.onclick = () => window.focus();
    } catch { /* izin yoksa geç */ }
  }

  async function enableNotif() {
    try {
      const p = await Notification.requestPermission();
      notifRef.current = p;
      setNotifPerm(p);
    } catch { /* desteklenmiyor */ }
  }

  async function send() {
    setErr("");
    const myName = meRef.current;
    const p = peerRef.current;
    const key = roomKeyRef.current;
    const text = draft.trim();
    if (!text || !key || !myName || !p || sending) return;
    // aynı metin 2 sn içinde tekrar gönderilmek istenirse yoksay (çift Enter/çift tık)
    const now = Date.now();
    if (lastSendRef.current.t === text && now - lastSendRef.current.at < 2000) return;
    lastSendRef.current = { t: text, at: now };
    const myReply = reply;
    try {
      const { ivB64, ctB64 } = await encryptText(key, JSON.stringify(envelope("text", text)));
      // iyimser UI: mesajı bekletmeden göster, sunucuya arka planda yaz
      const entry: ChatMsg = { from: myName, to: p, iv: ivB64, ct: ctB64, ts: Date.now(), kind: "text", plain: text, mine: true, reply: myReply ?? undefined };
      cachePut(ctB64, entry);
      setMsgs((prev) => [...prev, entry]);
      setDraft("");
      setReply(null);
      const ok = await publish("text", ivB64, ctB64);
      if (!ok) setInfo("📡 Bağlantı yok — mesaj kuyruğa alındı, internet gelince gidecek.");
    } catch (e) {
      lastSendRef.current = { t: "", at: 0 }; // başarısızsa kilidi aç, tekrar denensin
      setErr(e instanceof Error && e.message === "depo-dolu" ? "Tarayıcı deposu doldu." : "Gönderilemedi.");
      await refresh();
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
    const myReply = reply;
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
      const entry: ChatMsg = {
        from: meRef.current!, to: peerRef.current, iv: ivB64, ct: ctB64, ts: Date.now(),
        kind: "image", plain: "data:image/jpeg;base64," + bufToB64(bytes), mine: true, reply: myReply ?? undefined,
      };
      cachePut(ctB64, entry);
      setMsgs((prev) => [...prev, entry]);
      setReply(null);
      setInfo("");
      const okImg = await publish("image", ivB64, ctB64);
      if (!okImg) setInfo("📡 Bağlantı yok — resim kuyruğa alındı, internet gelince gidecek.");
    } catch (e) {
      setErr(e instanceof Error && e.message === "depo-dolu" ? "Tarayıcı deposu doldu (demo modu limiti)." : e instanceof Error ? "Gönderilemedi: " + e.message : "Resim gönderilemedi.");
      setInfo("");
      await refresh();
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
    const myReply = reply;
    const previewUrl = URL.createObjectURL(file);
    try {
      setInfo("Video şifrelenip yükleniyor...");
      const bytes = new Uint8Array(await file.arrayBuffer());
      const { ivB64, ctB64 } = await encryptBytes(key, bytes);
      const path = `${meRef.current}/${Date.now()}-${Math.random().toString(36).slice(2)}.enc`;
      const { error: upErr } = await supabase!.storage
        .from("chat-media")
        .upload(path, new Blob([b64ToBuf(ctB64)], { type: "application/octet-stream" }));
      if (upErr) {
        URL.revokeObjectURL(previewUrl);
        setErr("Yüklenemedi: " + upErr.message);
        setInfo("");
        return;
      }
      const payload = JSON.stringify(envelope("video", path, { biv: ivB64 }));
      const e2 = await encryptText(key, payload);
      const entry: ChatMsg = {
        from: meRef.current!, to: peerRef.current, iv: e2.ivB64, ct: e2.ctB64, ts: Date.now(),
        kind: "video", plain: previewUrl, mine: true, reply: myReply ?? undefined,
      };
      cachePut(e2.ctB64, entry);
      setMsgs((prev) => [...prev, entry]);
      setReply(null);
      setInfo("");
      const okVid = await publish("video", e2.ivB64, e2.ctB64);
      if (!okVid) setInfo("📡 Bağlantı yok — video kuyruğa alındı, internet gelince gidecek.");
    } catch (e) {
      URL.revokeObjectURL(previewUrl);
      setErr(e instanceof Error ? "Gönderilemedi: " + e.message : "Video gönderilemedi.");
      setInfo("");
      await refresh();
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
    setMobileTab("people");
    setUnread({});
    keyCacheRef.current = {};
    seenRef.current = {};
    baseSetRef.current = false;
    msgCache.current.clear();
    await clearSession();
    setTab("auth");
  }

  if (booting) {
    return (
      <main className="min-h-screen bg-[var(--bg)] text-[var(--ink)] flex items-center justify-center">
        <p className="text-sm text-[var(--muted)]">🔒 Oturum açılıyor...</p>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-[var(--bg)] text-[var(--ink)] p-4 sm:p-6">
      <div className="max-w-5xl mx-auto space-y-4 flex flex-col min-h-[calc(100vh-2rem)] sm:min-h-[calc(100vh-3rem)]">
        <header className="flex items-center justify-between">
          <h1 className="text-xl font-bold">🔒 E2E Chat <span className="text-xs font-normal text-[var(--muted)]">uçtan uca şifreli</span></h1>
          <div className="flex items-center gap-2">
            <div className="text-xs text-[var(--muted)] hidden sm:block">
              {supabaseConfigured ? "● Supabase bağlı" : "○ Demo modu (yerel sunucu simülasyonu)"}
            </div>
            <div className="relative">
              <button onClick={() => setShowSettings((v) => !v)} title="Tema" className="bg-[var(--input)] hover:bg-[var(--btn-hi)] rounded-lg px-2 py-1">🎨</button>
              {showSettings && (
                <div className="absolute right-0 top-9 z-20 bg-[var(--panel)] border border-[var(--border)] rounded-xl p-3 w-60 space-y-2 shadow-xl">
                  <p className="text-xs text-[var(--muted)] font-semibold">Tema</p>
                  <div className="grid grid-cols-2 gap-1">
                    {THEMES.map((t) => (
                      <button key={t.id} onClick={() => setTheme(t.id)}
                        className={`flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm ${theme === t.id ? "bg-[var(--out)] text-[var(--out-ink)]" : "bg-[var(--input)]"}`}>
                        <span className="flex -space-x-1">
                          {t.dots.map((d) => (
                            <span key={d} className="w-3 h-3 rounded-full border border-black/30" style={{ background: d }} />
                          ))}
                        </span>
                        {t.name}
                      </button>
                    ))}
                  </div>
                  {theme === "custom" && (
                    <div className="space-y-1 pt-1">
                      {([["bg", "Arka plan"], ["panel", "Kart"], ["accent", "Vurgu"], ["ink", "Yazı"]] as const).map(([k, label]) => (
                        <label key={k} className="flex items-center justify-between text-xs text-[var(--muted)]">
                          {label}
                          <input type="color" value={custom[k]} onChange={(e) => setCustom((c) => ({ ...c, [k]: e.target.value }))}
                            className="w-10 h-7 rounded cursor-pointer bg-transparent" />
                        </label>
                      ))}
                      <p className="text-[11px] text-[var(--faint)]">Diğer tonlar otomatik türetilir.</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </header>

        {tab === "auth" || !me ? (
          <section className="bg-[var(--panel)] rounded-2xl p-5 space-y-3 border border-[var(--border)] max-w-md w-full mx-auto">
            <h2 className="font-semibold">Rumuz + şifre ile giriş</h2>
            <p className="text-sm text-[var(--muted)]">
              Şifren sunucuya hiç gitmez. Özel anahtarın şifrenle şifrelenip saklanır. Sunucu sadece açık anahtar ve şifreli mesaj görür.
            </p>
            <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="rumuz (örn. ayse)"
              className="w-full bg-[var(--input)] rounded-lg px-3 py-2 outline-none" />
            <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" placeholder="şifre"
              className="w-full bg-[var(--input)] rounded-lg px-3 py-2 outline-none" />
            <div className="flex gap-2">
              <button onClick={register} className="flex-1 bg-[var(--btn)] hover:bg-[var(--btn-hi)] rounded-lg py-2">Kayıt ol</button>
              <button onClick={login} className="flex-1 bg-[var(--accent)] hover:bg-[var(--accent-hi)] text-[var(--accent-ink)] rounded-lg py-2 font-semibold">Giriş</button>
            </div>
            <label className="text-sm flex items-center gap-2 cursor-pointer text-[var(--ink)]">
              <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
              Oturumu açık tut (bu cihazda şifre sorma)
            </label>
            {err && <p className="text-red-400 text-sm">{err}</p>}
            {info && <p className="text-[var(--accent-hi)] text-sm">{info}</p>}
            <details className="text-xs text-[var(--muted)]">
              <summary className="cursor-pointer">İki kişiyi aynı tarayıcıda nasıl denersin?</summary>
              <p className="mt-1">1. ayse olarak kayıt ol → giriş → açık anahtarını kopyala → çıkış. 2. mehmet olarak kayıt ol → giriş → kişi: ayse + ayse&apos;nin anahtarını yapıştır → bağlan. Mesaj gönder. Sonra ayse ile giriş yapıp tersini yap.</p>
            </details>
          </section>
        ) : (
          <div className="flex flex-col flex-1 min-h-0">
            <div className="flex items-center justify-between">
              <p>Merhaba <b>{me}</b> 👋</p>
              <div className="flex items-center gap-2">
                {notifPerm !== "granted" ? (
                  <button onClick={enableNotif} title="Bildirimleri aç" className="text-xs bg-[var(--input)] hover:bg-[var(--btn-hi)] rounded-lg px-2 py-1">🔔 Bildirimleri aç</button>
                ) : (
                  <span title="Bildirimler açık" className="text-xs text-[var(--accent-hi)]">🔔 Açık</span>
                )}
                <button onClick={() => setMuted((v) => !v)} title={muted ? "Sesi aç" : "Sessize al"} className="text-xs bg-[var(--input)] hover:bg-[var(--btn-hi)] rounded-lg px-2 py-1">
                  {muted ? "🔇" : "🔊"}
                </button>
                <button onClick={logout} className="text-xs text-[var(--muted)] underline">çıkış</button>
              </div>
            </div>

            {/* mobil sekmeler */}
            <div className="grid grid-cols-2 gap-2 mt-3 md:hidden">
              <button onClick={() => setMobileTab("people")}
                className={`rounded-lg py-2 font-semibold ${mobileTab === "people" ? "bg-[var(--out)] text-[var(--out-ink)]" : "bg-[var(--input)]"}`}>
                👥 Kişiler{unreadTotal > 0 ? ` (${unreadTotal})` : ""}
              </button>
              <button onClick={() => setMobileTab("chat")}
                className={`rounded-lg py-2 font-semibold ${mobileTab === "chat" ? "bg-[var(--out)] text-[var(--out-ink)]" : "bg-[var(--input)]"}`}>💬 Sohbet</button>
            </div>

            {err && <p className="text-red-400 text-sm mt-2">{err}</p>}
            {info && <p className="text-[var(--accent-hi)] text-sm mt-2">{info}</p>}
            {connDown && <p className="text-xs text-amber-400 mt-2">📡 Bağlantı kopuk — yeniden deneniyor, gönderdiklerin kuyrukta bekliyor.</p>}

            <div className="grid md:grid-cols-[260px_1fr] gap-4 mt-3 flex-1 min-h-0">
              {/* KİŞİLER */}
              <aside className={`${mobileTab === "people" ? "block" : "hidden"} md:block bg-[var(--panel)] rounded-2xl p-4 space-y-3 border border-[var(--border)] h-fit md:sticky md:top-4`}>
                <h2 className="font-semibold text-sm text-[var(--ink)]">👥 Kişiler</h2>
                {contacts.length === 0 && (
                  <p className="text-xs text-[var(--faint)]">Henüz kişi yok. Aşağıdan ilk kişini ekle 👇</p>
                )}
                <div className="space-y-1">
                  {contacts.map((c) => (
                    <div key={c.name} className={`flex items-center gap-1 rounded-lg pr-1 ${peer === c.name && roomKey ? "bg-[var(--out)] text-[var(--out-ink)]" : "bg-[var(--input)]"}`}>
                      <button onClick={() => connectPeer(c.name)} className="flex-1 text-left px-3 py-2 font-medium truncate">💬 {c.name}</button>
                      {(unread[c.name] ?? 0) > 0 && (
                        <span className="bg-red-500 text-white text-xs font-bold rounded-full min-w-5 h-5 flex items-center justify-center px-1">{unread[c.name]}</span>
                      )}
                      <button
                        title={`${c.name} kişisini sil`}
                        onClick={() => me && setContacts(removeContact(me, c.name))}
                        className="text-[var(--faint)] hover:text-red-400 rounded px-1"
                      >×</button>
                    </div>
                  ))}
                </div>
                <details className="text-sm">
                  <summary className="cursor-pointer text-[var(--accent-hi)] font-medium">＋ Yeni kişi</summary>
                  <div className="space-y-2 mt-2">
                    <div className="flex gap-2">
                      <input value={peer} onChange={(e) => setPeer(e.target.value)} placeholder="rumuz (örn. mehmet)"
                        className="flex-1 min-w-0 bg-[var(--input)] rounded-lg px-3 py-2 outline-none text-sm" />
                      <button onClick={() => connectPeer()} className="bg-[var(--accent)] text-[var(--accent-ink)] rounded-lg px-3 py-2 font-semibold text-sm shrink-0">Bağlan</button>
                    </div>
                    <textarea value={peerJwkText} onChange={(e) => setPeerJwkText(e.target.value)}
                      placeholder="Açık anahtar (Supabase bağlı değilse gerekli)"
                      className="w-full bg-[var(--input)] rounded-lg px-3 py-2 outline-none text-xs h-14" />
                  </div>
                </details>
                <details className="text-xs text-[var(--muted)]">
                  <summary className="cursor-pointer">Benim açık anahtarım</summary>
                  <pre className="text-[11px] bg-[var(--input)] rounded-lg p-2 overflow-auto max-h-24 mt-1">{JSON.stringify(myPubJwk)}</pre>
                  <button onClick={() => myPubJwk && navigator.clipboard.writeText(JSON.stringify(myPubJwk))}
                    className="mt-1 text-xs bg-[var(--btn)] rounded px-2 py-1">kopyala</button>
                </details>
              </aside>

              {/* SOHBET */}
              <section className={`${mobileTab === "chat" ? "flex" : "hidden"} md:flex flex-col bg-[var(--panel)] rounded-2xl p-4 sm:p-5 space-y-3 border border-[var(--accent-dim)] min-h-[60vh] md:min-h-[65vh]`}>
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-[var(--accent-hi)]">
                    {roomKey ? `💬 ${peer} ile güvenli sohbet` : "💬 Sohbet"}
                  </h3>
                  {roomKey && <button onClick={() => refresh()} title="Yenile" className="bg-[var(--btn)] rounded-lg px-2 py-1 text-sm">↻</button>}
                </div>
                {!roomKey ? (
                  <p className="text-sm text-[var(--faint)] flex-1 flex items-center justify-center text-center">
                    Başlamak için kişilerinden birini seç<br />veya yeni kişi ekle 👈
                  </p>
                ) : (
                  <>
                    <div className="space-y-2 flex-1 overflow-auto min-h-[40vh]">
                      {msgs.length === 0 && <p className="text-sm text-[var(--faint)]">Henüz mesaj yok. İlk şifreli mesajı gönder!</p>}
                      {msgs.map((m, i) => (
                        <div key={i} className={`max-w-[85%] rounded-xl px-3 py-2 text-sm ${m.mine ? "ml-auto bg-[var(--out)] text-[var(--out-ink)]" : "bg-[var(--btn)]"}`}>
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
                            <p className="break-words">{m.plain}</p>
                          )}
                          <p className="text-[10px] opacity-60 mt-1 flex items-center gap-2">
                            <span>{m.from} • {new Date(m.ts).toLocaleTimeString()}</span>
                            <button title="Yanıtla" onClick={() => setReply({ from: m.from, snippet: snippetOf(m) })} className="hover:opacity-100 opacity-70">↩</button>
                          </p>
                        </div>
                      ))}
                    </div>
                    {reply && (
                      <div className="flex items-center gap-2 text-xs bg-[var(--input)] rounded-lg px-3 py-2">
                        <span className="flex-1 truncate"><b>{reply.from}:</b> {reply.snippet}</span>
                        <button onClick={() => setReply(null)} className="text-[var(--muted)] hover:text-[var(--ink)]">✕</button>
                      </div>
                    )}
                    <div className="flex gap-2 relative">
                      <input value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => e.key === "Enter" && send()}
                        placeholder="şifreli mesaj yaz..." className="flex-1 min-w-0 bg-[var(--input)] rounded-lg px-3 py-2 outline-none" />
                      <div className="sm:hidden">
                        <button onClick={() => setShowAttach((v) => !v)} title="Ekle" className="bg-[var(--btn)] rounded-lg px-3 py-2">＋</button>
                        {showAttach && (
                          <div className="absolute bottom-12 right-0 bg-[var(--input)] border border-[var(--border)] rounded-xl p-2 flex gap-1 z-10">
                            <button title="Emoji" onClick={() => { setShowEmoji((v) => !v); setShowAttach(false); }} className="text-xl hover:bg-[var(--btn-hi)] rounded p-1">😊</button>
                            <label title="Şifreli resim" className="text-xl hover:bg-[var(--btn-hi)] rounded p-1 cursor-pointer">📷
                              <input type="file" accept="image/*" className="hidden" onChange={(e) => {
                                const f = e.target.files?.[0];
                                if (f) sendImage(f);
                                e.target.value = "";
                                setShowAttach(false);
                              }} />
                            </label>
                            <label title="Şifreli video (max 25MB)" className="text-xl hover:bg-[var(--btn-hi)] rounded p-1 cursor-pointer">🎬
                              <input type="file" accept="video/*" className="hidden" onChange={(e) => {
                                const f = e.target.files?.[0];
                                if (f) sendVideo(f);
                                e.target.value = "";
                                setShowAttach(false);
                              }} />
                            </label>
                          </div>
                        )}
                      </div>
                      <button onClick={() => setShowEmoji((v) => !v)} title="Emoji" className="hidden sm:block bg-[var(--btn)] hover:bg-[var(--btn-hi)] rounded-lg px-3 py-2">😊</button>
                      <label className="hidden sm:block bg-[var(--btn)] hover:bg-[var(--btn-hi)] rounded-lg px-3 py-2 cursor-pointer" title="Şifreli resim gönder">
                        📷
                        <input type="file" accept="image/*" className="hidden" onChange={(e) => {
                          const f = e.target.files?.[0];
                          if (f) sendImage(f);
                          e.target.value = "";
                        }} />
                      </label>
                      <label className="hidden sm:block bg-[var(--btn)] hover:bg-[var(--btn-hi)] rounded-lg px-3 py-2 cursor-pointer" title="Şifreli video gönder (max 25MB)">
                        🎬
                        <input type="file" accept="video/*" className="hidden" onChange={(e) => {
                          const f = e.target.files?.[0];
                          if (f) sendVideo(f);
                          e.target.value = "";
                        }} />
                      </label>
                      <button onClick={(e) => { e.currentTarget.blur(); send(); }} disabled={sending} className="bg-[var(--accent)] text-[var(--accent-ink)] rounded-lg px-3 sm:px-4 py-2 font-semibold disabled:opacity-50 shrink-0">
                        {sending ? "…" : <><span className="hidden sm:inline">Gönder</span><span className="sm:hidden">➤</span></>}
                      </button>
                      {showEmoji && (
                        <div className="absolute bottom-12 right-0 bg-[var(--input)] border border-[var(--border)] rounded-xl p-2 grid grid-cols-8 gap-1 max-w-[280px] z-10">
                          {EMOJIS.map((e) => (
                            <button key={e} onClick={() => setDraft((d) => d + e)} className="text-xl hover:bg-[var(--btn-hi)] rounded p-0.5">{e}</button>
                          ))}
                        </div>
                      )}
                    </div>
                  </>
                )}
              </section>
            </div>
          </div>
        )}

        <footer className="text-xs text-[var(--faint)] leading-relaxed">
          Nasıl çalışıyor? Kayıtta ECDH P-256 kimlik anahtarı üretilir, özel anahtar şifrenle (PBKDF2 150k + AES-GCM) kilitlenir.
          Sohbette ECDH ile ortak oda anahtarı türetilir, her mesaj AES-GCM ile şifrelenir. Sunucu (yerel simülasyon veya Supabase) sadece iv + şifreli metin görür.
          Ücretsiz yayın: bu repo Vercel&apos;e + Supabase ücretsiz katmanına bağlanır. <code>supabase/schema.sql</code>&apos;i çalıştır, <code>.env.example</code>&apos;deki 2 anahtarı Vercel&apos;e ekle.
        </footer>
      </div>
    </main>
  );
}

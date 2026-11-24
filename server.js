/* ============================================================
   ER Yapı İnşaat — Web sitesi + Yönetim Paneli sunucusu
   Çalıştırma:  npm start   (veya BASLAT.bat)
   Site:        http://localhost:3000
   Panel:       http://localhost:3000/admin
   ============================================================ */
const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
const SEED_FILE = path.join(DATA_DIR, "varsayilan.json");
const AUTH_FILE = path.join(DATA_DIR, "admin.json");
const PUBLIC_DIR = path.join(ROOT, "public");
const UPLOAD_DIR = path.join(PUBLIC_DIR, "uploads");
const DEFAULT_PASSWORD = process.env.ADMIN_SIFRE || "eryapi2026";

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.copyFileSync(SEED_FILE, DB_FILE);

// ---------------- Veritabanı (JSON dosyası) ----------------
let db = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
db.mesajlar = db.mesajlar || [];
function save() {
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

// ---------------- Şifre / oturum ----------------
function hashPassword(pw, salt = crypto.randomBytes(16).toString("hex")) {
  return { salt, hash: crypto.scryptSync(pw, salt, 64).toString("hex") };
}
if (!fs.existsSync(AUTH_FILE)) {
  fs.writeFileSync(AUTH_FILE, JSON.stringify({ ...hashPassword(DEFAULT_PASSWORD), secret: crypto.randomBytes(32).toString("hex") }, null, 2));
}
let auth = JSON.parse(fs.readFileSync(AUTH_FILE, "utf8"));
function checkPassword(pw) {
  const h = crypto.scryptSync(String(pw || ""), auth.salt, 64);
  return crypto.timingSafeEqual(h, Buffer.from(auth.hash, "hex"));
}
const SESSION_HOURS = 12;
function makeToken() {
  const exp = Date.now() + SESSION_HOURS * 3600e3;
  return exp + "." + crypto.createHmac("sha256", auth.secret).update(String(exp)).digest("hex");
}
function validToken(t) {
  if (!t) return false;
  const [exp, sig] = String(t).split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const good = crypto.createHmac("sha256", auth.secret).update(exp).digest("hex");
  return sig.length === good.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good));
}
function getCookie(req, name) {
  const m = (req.headers.cookie || "").match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : "";
}
function requireAuth(req, res, next) {
  if (validToken(getCookie(req, "eryapi_oturum"))) return next();
  res.status(401).json({ hata: "Oturum gerekli" });
}
const fails = new Map(); // basit giriş denemesi sınırı
function tooMany(ip) {
  const f = fails.get(ip);
  return f && f.n >= 6 && Date.now() - f.t < 10 * 60e3;
}

// ---------------- Uygulama ----------------
const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "2mb" }));

const str = (v, max = 2000) => String(v ?? "").trim().slice(0, max);
const uid = () => Date.now().toString(36) + crypto.randomBytes(3).toString("hex");

// ---- Herkese açık API ----
app.get("/api/site", (req, res) => {
  const { mesajlar, ...pub } = db;
  res.set("Cache-Control", "no-store").json(pub);
});

const msgLimit = new Map();
app.post("/api/mesaj", (req, res) => {
  const ip = req.ip;
  const l = msgLimit.get(ip) || [];
  const recent = l.filter((t) => Date.now() - t < 60 * 60e3);
  if (recent.length >= 8) return res.status(429).json({ hata: "Çok fazla mesaj gönderildi, lütfen daha sonra deneyin." });
  const b = req.body || {};
  if (b.website) return res.json({ ok: true }); // bot tuzağı
  const ad = str(b.ad, 120), telefon = str(b.telefon, 40);
  if (!ad || !telefon) return res.status(400).json({ hata: "Ad soyad ve telefon gerekli." });
  db.mesajlar.unshift({ id: uid(), ad, telefon, tur: str(b.tur, 80), mesaj: str(b.mesaj, 3000), tarih: new Date().toISOString(), okundu: false });
  db.mesajlar = db.mesajlar.slice(0, 2000);
  save();
  recent.push(Date.now()); msgLimit.set(ip, recent);
  res.json({ ok: true });
});

// ---- Giriş ----
app.post("/api/giris", (req, res) => {
  const ip = req.ip;
  if (tooMany(ip)) return res.status(429).json({ hata: "Çok fazla hatalı deneme. 10 dakika sonra tekrar deneyin." });
  if (!checkPassword(req.body && req.body.sifre)) {
    const f = fails.get(ip) || { n: 0, t: Date.now() };
    if (Date.now() - f.t > 10 * 60e3) { f.n = 0; f.t = Date.now(); }
    f.n++; fails.set(ip, f);
    return res.status(401).json({ hata: "Şifre hatalı." });
  }
  fails.delete(ip);
  const secure = req.secure || req.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `eryapi_oturum=${makeToken()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_HOURS * 3600}${secure}`);
  res.json({ ok: true });
});
app.post("/api/cikis", (req, res) => {
  res.setHeader("Set-Cookie", "eryapi_oturum=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
  res.json({ ok: true });
});
app.get("/api/oturum", (req, res) => res.json({ giris: validToken(getCookie(req, "eryapi_oturum")) }));

// ---- Yönetim API ----
const admin = express.Router();
admin.use(requireAuth);

admin.get("/veri", (req, res) => res.set("Cache-Control", "no-store").json(db));

// Bölüm güncelleme (ayarlar, metinler, rakamlar, hizmetler, surec, gorseller)
const SECTIONS = {
  ayarlar: (v) => Object.fromEntries(Object.entries(db.ayarlar).map(([k]) => [k, str(v[k], 500)])),
  metinler: (v) => Object.fromEntries(Object.entries(db.metinler).map(([k]) => [k, str(v[k], 3000)])),
  rakamlar: (v) => (Array.isArray(v) ? v : []).slice(0, 4).map((r) => ({ deger: str(r.deger, 20), etiket: str(r.etiket, 160) })),
  hizmetler: (v) => db.hizmetler.map((h) => { const n = (Array.isArray(v) ? v : []).find((x) => x.id === h.id) || h; return { id: h.id, ad: str(n.ad, 80) || h.ad, aciklama: str(n.aciklama, 400) }; }),
  surec: (v) => (Array.isArray(v) ? v : []).slice(0, 6).map((s) => ({ baslik: str(s.baslik, 80), metin: str(s.metin, 400) })),
  gorseller: (v) => ({
    heroVideo: str(v.heroVideo, 300),
    heroSlaytlar: (Array.isArray(v.heroSlaytlar) ? v.heroSlaytlar : []).slice(0, 8).map((x) => str(x, 300)).filter(Boolean),
    araBolum: str(v.araBolum, 300),
    galeri: (Array.isArray(v.galeri) ? v.galeri : []).slice(0, 5).map((g) => ({ src: str(g.src, 300), etiket: str(g.etiket, 60) })).filter((g) => g.src),
  }),
};
admin.put("/bolum/:ad", (req, res) => {
  const fn = SECTIONS[req.params.ad];
  if (!fn) return res.status(404).json({ hata: "Bölüm yok" });
  db[req.params.ad] = fn(req.body || {});
  save();
  res.json(db[req.params.ad]);
});

// Projeler
const KATS = () => db.hizmetler.map((h) => h.id);
function cleanProject(b, old = {}) {
  return {
    id: old.id || uid(),
    baslik: str(b.baslik, 120) || "Adsız proje",
    kategori: KATS().includes(b.kategori) ? b.kategori : KATS()[0],
    konum: str(b.konum, 120),
    yil: str(b.yil, 10),
    durum: b.durum === "Devam ediyor" ? "Devam ediyor" : "Tamamlandı",
    aciklama: str(b.aciklama, 3000),
    kapak: str(b.kapak, 300),
    galeri: (Array.isArray(b.galeri) ? b.galeri : []).slice(0, 30).map((x) => str(x, 300)).filter(Boolean),
  };
}
admin.post("/projeler", (req, res) => {
  const p = cleanProject(req.body || {});
  db.projeler.unshift(p); save(); res.json(p);
});
admin.put("/projeler/:id", (req, res) => {
  const i = db.projeler.findIndex((p) => p.id === req.params.id);
  if (i < 0) return res.status(404).json({ hata: "Proje bulunamadı" });
  db.projeler[i] = cleanProject(req.body || {}, db.projeler[i]); save(); res.json(db.projeler[i]);
});
admin.delete("/projeler/:id", (req, res) => {
  db.projeler = db.projeler.filter((p) => p.id !== req.params.id); save(); res.json({ ok: true });
});
admin.post("/projeler-sira", (req, res) => {
  const ids = Array.isArray(req.body && req.body.ids) ? req.body.ids : [];
  const map = new Map(db.projeler.map((p) => [p.id, p]));
  const sorted = ids.map((id) => map.get(id)).filter(Boolean);
  db.projeler = [...sorted, ...db.projeler.filter((p) => !ids.includes(p.id))];
  save(); res.json({ ok: true });
});

// Mesajlar
admin.put("/mesajlar/:id", (req, res) => {
  const m = db.mesajlar.find((x) => x.id === req.params.id);
  if (!m) return res.status(404).json({ hata: "Mesaj yok" });
  m.okundu = !!(req.body && req.body.okundu); save(); res.json(m);
});
admin.delete("/mesajlar/:id", (req, res) => {
  db.mesajlar = db.mesajlar.filter((x) => x.id !== req.params.id); save(); res.json({ ok: true });
});

// Dosya yükleme
const IMG = { "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp" };
const VID = { "video/mp4": ".mp4", "video/webm": ".webm" };
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => cb(null, uid() + (IMG[file.mimetype] || VID[file.mimetype])),
  }),
  limits: { fileSize: 250 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, !!(IMG[file.mimetype] || VID[file.mimetype])),
});
admin.post("/yukle", upload.single("dosya"), (req, res) => {
  if (!req.file) return res.status(400).json({ hata: "Desteklenmeyen dosya. JPG, PNG, WEBP, MP4 veya WEBM yükleyin." });
  if (IMG[req.file.mimetype] && req.file.size > 20 * 1024 * 1024) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ hata: "Görsel 20 MB'tan büyük olamaz." });
  }
  res.json({ yol: "uploads/" + req.file.filename });
});

// Şifre ve yedek
admin.post("/sifre", (req, res) => {
  const { eski, yeni } = req.body || {};
  if (!checkPassword(eski)) return res.status(400).json({ hata: "Mevcut şifre hatalı." });
  if (!yeni || String(yeni).length < 8) return res.status(400).json({ hata: "Yeni şifre en az 8 karakter olmalı." });
  auth = { ...hashPassword(String(yeni)), secret: crypto.randomBytes(32).toString("hex") };
  fs.writeFileSync(AUTH_FILE, JSON.stringify(auth, null, 2));
  res.setHeader("Set-Cookie", `eryapi_oturum=${makeToken()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_HOURS * 3600}`);
  res.json({ ok: true });
});
admin.get("/yedek", (req, res) => {
  res.setHeader("Content-Disposition", `attachment; filename="eryapi-yedek-${new Date().toISOString().slice(0, 10)}.json"`);
  res.json(db);
});
admin.post("/geri-yukle", express.json({ limit: "20mb" }), (req, res) => {
  const b = req.body;
  if (!b || !Array.isArray(b.projeler) || !b.ayarlar || !b.metinler) return res.status(400).json({ hata: "Geçersiz yedek dosyası." });
  db = { ...db, ...b, mesajlar: Array.isArray(b.mesajlar) ? b.mesajlar : db.mesajlar };
  save(); res.json({ ok: true });
});

app.use("/api/yonetim", admin);
app.use("/api", (req, res) => res.status(404).json({ hata: "Bulunamadı" }));

// ---- Statik dosyalar ----
app.use("/admin", express.static(path.join(ROOT, "admin"), { index: "index.html" }));
app.use(express.static(PUBLIC_DIR, { extensions: ["html"] }));
app.use((err, req, res, next) => {
  if (err && err.code === "LIMIT_FILE_SIZE") return res.status(400).json({ hata: "Dosya çok büyük (en fazla 250 MB)." });
  console.error(err);
  res.status(500).json({ hata: "Sunucu hatası" });
});

app.listen(PORT, () => {
  console.log("\n  ER Yapı İnşaat çalışıyor");
  console.log("  Site:  http://localhost:" + PORT);
  console.log("  Panel: http://localhost:" + PORT + "/admin\n");
});

// بک‌اند مددی دکور: سفارش، پرداخت زرین‌پال، پنل مدیریت (JWT) و رویداد زنده (SSE)
require("dotenv").config();
const express = require("express"), helmet = require("helmet"), rate = require("express-rate-limit");
const jwt = require("jsonwebtoken"), crypto = require("crypto"), fs = require("fs"), path = require("path");
const { PORT = 3000, SITE_URL = "http://localhost:3000", MERCHANT_ID, JWT_SECRET, ADMIN_USER = "admin", ADMIN_PASS, ZP_SANDBOX } = process.env;
if (!JWT_SECRET || !ADMIN_PASS || !MERCHANT_ID) { console.error("فایل .env را کامل کنید"); process.exit(1); }

const ZP = ZP_SANDBOX ? "https://sandbox.zarinpal.com/pg/v4/payment" : "https://api.zarinpal.com/pg/v4/payment";
const START = ZP_SANDBOX ? "https://sandbox.zarinpal.com/pg/StartPay/" : "https://www.zarinpal.com/pg/StartPay/";
const DB = path.join(__dirname, "data.json");
const SEED = [["مبل راحتی نیلوفر", 18500000], ["چراغ ایستاده آرتا", 2900000], ["گلدان سرامیکی مات", 780000], ["آینه قدی ماه", 4200000],
  ["میز عسلی چوبی", 3400000], ["گیاه زینتی مونسترا", 950000], ["فرش دست‌باف مدرن", 12800000], ["ساعت دیواری مینیمال", 1250000]]
  .map(([name, price], id) => ({ id, name, price }));
const load = () => { try { return JSON.parse(fs.readFileSync(DB, "utf8")); } catch { return { orders: [], products: SEED }; } };
const save = d => fs.writeFileSync(DB, JSON.stringify(d, null, 1));
const sha = s => crypto.createHash("sha256").update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

const app = express();
app.use(helmet({ contentSecurityPolicy: false }), express.json({ limit: "20kb" }));
const clients = new Set();
const push = ev => clients.forEach(r => r.write(`data: ${JSON.stringify(ev)}\n\n`));
const zp = async (ep, body) => (await fetch(`${ZP}/${ep}.json`, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify({ merchant_id: MERCHANT_ID, ...body }) })).json();

// ---- عمومی ----
app.get("/api/products", (_, res) => res.json(load().products));

app.post("/api/checkout", rate({ windowMs: 6e4, max: 10 }), async (req, res) => {
  try {
    const { customer: c = {}, items = [] } = req.body, db = load();
    if (!/^09\d{9}$/.test(c.phone) || !/^\d{10}$/.test(c.postal) || !c.name || !c.city || !c.addr) return res.status(400).json({ error: "اطلاعات خریدار ناقص است" });
    const lines = items.map(i => { const p = db.products.find(x => x.id === +i.id); const q = Math.min(20, Math.max(1, +i.q | 0)); return p && { n: p.name, p: p.price, q }; });
    if (!lines.length || lines.includes(undefined)) return res.status(400).json({ error: "سبد خرید نامعتبر است" });
    const total = lines.reduce((a, l) => a + l.p * l.q, 0); // قیمت از سرور محاسبه می‌شود نه از مرورگر
    const id = "MD-" + crypto.randomInt(100000, 999999);
    const r = await zp("request", { amount: total * 10, callback_url: `${SITE_URL}/api/verify?order=${id}`, description: `سفارش ${id}`, metadata: { mobile: c.phone } });
    if (r.data?.code !== 100) return res.status(502).json({ error: "خطا در اتصال به درگاه", details: r.errors });
    db.orders.unshift({ id, ...c, items: lines, total, status: "pending", authority: r.data.authority, ts: Date.now() });
    save(db); res.json({ id, url: START + r.data.authority });
  } catch (e) { console.error(e); res.status(500).json({ error: "خطای سرور" }); }
});

app.get("/api/verify", async (req, res) => { // بازگشت از زرین‌پال
  const db = load(), o = db.orders.find(x => x.id === req.query.order && x.authority === req.query.Authority);
  if (!o) return res.redirect(`${SITE_URL}/?failed=1`);
  if (o.status !== "pending") return res.redirect(`${SITE_URL}/?paid=${o.id}`);
  if (req.query.Status !== "OK") { o.status = "failed"; save(db); return res.redirect(`${SITE_URL}/?failed=${o.id}`); }
  try {
    const r = await zp("verify", { amount: o.total * 10, authority: o.authority });
    if ([100, 101].includes(r.data?.code)) { o.status = "paid"; o.refId = r.data.ref_id; o.last4 = r.data.card_pan?.slice(-4); save(db); push({ type: "order", order: o }); return res.redirect(`${SITE_URL}/?paid=${o.id}`); }
  } catch (e) { console.error(e); }
  o.status = "failed"; save(db); res.redirect(`${SITE_URL}/?failed=${o.id}`);
});

// ---- مدیر ----
app.post("/api/admin/login", rate({ windowMs: 15 * 6e4, max: 10 }), (req, res) => {
  const { user, pass } = req.body;
  if (same(user, ADMIN_USER) && same(pass, ADMIN_PASS)) return res.json({ token: jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "8h" }) });
  res.status(401).json({ error: "نام کاربری یا رمز اشتباه است" });
});
const auth = (req, res, next) => {
  try { jwt.verify((req.headers.authorization || "").slice(7) || req.query.token, JWT_SECRET); next(); } catch { res.status(401).json({ error: "دسترسی غیرمجاز" }); }
};
app.get("/api/admin/orders", auth, (_, res) => res.json(load().orders));
app.patch("/api/admin/orders/:id", auth, (req, res) => {
  const db = load(), o = db.orders.find(x => x.id === req.params.id);
  if (!o || !["paid", "ship", "done", "cancel"].includes(req.body.status)) return res.sendStatus(400);
  o.status = req.body.status; save(db); push({ type: "status", id: o.id, status: o.status }); res.json(o);
});
app.put("/api/admin/products/:id", auth, (req, res) => {
  const db = load(), p = db.products.find(x => x.id === +req.params.id), price = +req.body.price;
  if (!p || !(price >= 0)) return res.sendStatus(400);
  p.price = price; save(db); res.json(p);
});
app.get("/api/admin/stats", auth, (_, res) => {
  const ok = load().orders.filter(o => ["paid", "ship", "done"].includes(o.status)), sum = ok.reduce((a, o) => a + o.total, 0);
  res.json({ orders: ok.length, revenue: sum, average: ok.length ? Math.round(sum / ok.length) : 0, waiting: ok.filter(o => o.status === "paid").length });
});
app.get("/api/admin/stream", auth, (req, res) => { // رویداد زنده برای داشبورد
  res.set({ "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" }).flushHeaders();
  clients.add(res); req.on("close", () => clients.delete(res));
});

app.use(express.static(path.join(__dirname, "public"))); // فایل madadi-decor.html را اینجا به نام index.html بگذارید
app.listen(PORT, () => console.log(`http://localhost:${PORT}`));

import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";

export const dynamic = "force-dynamic";
const env = process.env;

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const json = (data, status = 200) =>
  Response.json(data, { status, headers: { "Cache-Control": "no-store" } });

// Server-only database client (secret key). Never sent to the browser.
let _db;
const db = () => (_db ??= createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false, autoRefreshToken: false } }));

/* ---------- talk to the Discord bot (signed requests) ---------- */
async function botFetch(method, path, body) {
  if (!env.BOT_API_URL || !env.BOT_API_SECRET) throw new Error("Bot API is not configured");
  const raw = body ? JSON.stringify(body) : "";
  const ts = String(Date.now());
  const sig = crypto.createHmac("sha256", env.BOT_API_SECRET)
    .update(`${ts}.${method}.${path}.${raw}`).digest("hex");
  const res = await fetch(env.BOT_API_URL.replace(/\/+$/, "") + path, {
    method,
    headers: { "Content-Type": "application/json", "x-lara-timestamp": ts, "x-lara-signature": sig },
    body: raw || undefined,
    cache: "no-store",
    signal: AbortSignal.timeout(8000)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Bot API error ${res.status}`);
  return data;
}

/* ---------- who is calling? ---------- */
async function getUser(req) {
  const token = (req.headers.get("authorization") || "").replace(/^Bearer /, "");
  if (!token) throw new HttpError(401, "Please log in");
  const { data, error } = await db().auth.getUser(token);
  if (error || !data?.user) throw new HttpError(401, "Session expired. Please log in again.");
  // Use the provider identity (set by Supabase), NOT user_metadata, which users can edit.
  const idn = (data.user.identities || []).find(i => i.provider === "discord");
  const d = idn?.identity_data || {};
  const discordId = String(d.provider_id || d.sub || idn?.id || "");
  if (!/^\d{17,20}$/.test(discordId)) throw new HttpError(403, "A Discord login is required");
  const username = String(d.custom_claims?.global_name || d.full_name || d.name || "Unknown").slice(0, 100);
  return { user: data.user, discordId, username, avatar: String(d.avatar_url || d.picture || "") };
}
async function rolesFor(discordId) {
  try { return await botFetch("GET", `/members/${discordId}/roles`); }
  catch (e) { console.error("Role check failed:", e.message); return { botError: true, isStaff: false, isAdmin: false }; }
}
async function needFlag(req, flag) {
  const u = await getUser(req);
  const r = await rolesFor(u.discordId);
  if (r.botError) throw new HttpError(503, "Cannot verify your roles right now (bot offline)");
  if (!r[flag]) throw new HttpError(403, "You do not have access");
  return { ...u, r };
}
async function readBody(req) {
  const t = await req.text();
  if (t.length > 100000) throw new HttpError(413, "Request too large");
  try { return JSON.parse(t || "{}"); } catch { throw new HttpError(400, "Invalid JSON"); }
}

/* ---------- application validation (same 24 questions as the form) ---------- */
const SHAPE = [6, 7, 7, 4];
function cleanAnswers(a) {
  if (!a || typeof a !== "object") throw new HttpError(400, "Missing answers");
  const out = {}; let n = 0;
  SHAPE.forEach((count, si) => {
    for (let qi = 0; qi < count; qi++) {
      n++;
      const k = `${si}-${qi}`;
      const long = si >= 2 || (si === 1 && qi >= 5);
      const v = typeof a[k] === "string" ? a[k].trim() : "";
      if (!v && k !== "3-3") throw new HttpError(400, `Question ${n} is required`);
      if (v.length > (long ? 3000 : 200)) throw new HttpError(400, `Answer to question ${n} is too long`);
      out[k] = v;
    }
  });
  return out;
}

/* ---------- requests coming FROM the Discord bot (same signature scheme) ---------- */
const seenSigs = new Map();
function verifyBot(req, raw) {
  const ts = req.headers.get("x-lara-timestamp") || "", sig = req.headers.get("x-lara-signature") || "";
  if (!env.BOT_API_SECRET || !/^\d{13}$/.test(ts) || Math.abs(Date.now() - Number(ts)) > 300000) return false;
  const expected = crypto.createHmac("sha256", env.BOT_API_SECRET)
    .update(`${ts}.${req.method}.${new URL(req.url).pathname}.${raw}`).digest("hex");
  const a = Buffer.from(sig, "hex"), b = Buffer.from(expected, "hex");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  for (const [k, t] of seenSigs) if (Date.now() - t > 360000) seenSigs.delete(k);
  if (seenSigs.has(sig)) return false;
  seenSigs.set(sig, Date.now());
  return true;
}

/* ---------- Melonly (weekly activity from shifts) ---------- */
async function melonlyAll(path) {
  const out = [];
  for (let page = 1; page <= 30; page++) {
    const r = await fetch(`https://api.melonly.xyz/api/v1${path}?page=${page}&limit=100`, {
      headers: { Authorization: "Bearer " + env.MELONLY_API_TOKEN }, cache: "no-store", signal: AbortSignal.timeout(8000) });
    if (!r.ok) throw new Error("Melonly responded " + r.status);
    const j = await r.json();
    out.push(...(j.data || []));
    if (page >= (j.totalPages || 1)) break;
  }
  return out;
}
const mcache = {};
async function cached(key, ms, fn) {
  const c = mcache[key];
  if (c && Date.now() - c.t < ms) return c.d;
  const d = await fn(); mcache[key] = { t: Date.now(), d }; return d;
}
const toSec = v => (v > 1e12 ? v / 1000 : v);
async function quotaFor(discordId) {
  if (!env.MELONLY_API_TOKEN) return { available: false, reason: "Melonly is not connected yet" };
  try {
    const members = await cached("members", 300000, () => melonlyAll("/server/members"));
    const m = members.find(x => Object.values(x).some(v => typeof v === "string" && v === discordId));
    if (!m) return { available: false, reason: "No Melonly profile is linked to your Discord account" };
    const shifts = await cached("shifts", 120000, () => melonlyAll("/server/shifts"));
    const now = new Date(), day = (now.getUTCDay() + 6) % 7;
    const weekStart = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - day) / 1000;
    let seconds = 0, count = 0;
    for (const s of shifts) {
      if (String(s.memberId) !== String(m.id)) continue;
      const start = toSec(Number(s.createdAt)), end = s.endedAt ? toSec(Number(s.endedAt)) : now.getTime() / 1000;
      if (!(start >= weekStart)) continue;
      seconds += Math.max(0, end - start); count++;
    }
    const target = Number(env.QUOTA_HOURS_WEEKLY) || null;
    return { available: true, hours: seconds / 3600, shifts: count, target };
  } catch (e) { console.error("Quota failed:", e.message); return { available: false, reason: "Melonly could not be reached" }; }
}

/* ---------- public data (cached, real numbers only) ---------- */
let statsCache = { t: 0, d: null };
async function stats() {
  if (statsCache.d && Date.now() - statsCache.t < 300000) return statsCache.d;
  const d = { robloxMembers: null, discordMembers: null, discordOnline: null };
  await Promise.all([
    (async () => {
      if (!env.ROBLOX_GROUP_ID) return;
      const r = await fetch(`https://groups.roblox.com/v1/groups/${encodeURIComponent(env.ROBLOX_GROUP_ID)}`, { signal: AbortSignal.timeout(6000) });
      if (r.ok) d.robloxMembers = (await r.json()).memberCount ?? null;
    })().catch(() => {}),
    (async () => {
      const code = env.DISCORD_INVITE_CODE || "Udns79wXpM";
      const r = await fetch(`https://discord.com/api/v10/invites/${code}?with_counts=true`, { signal: AbortSignal.timeout(6000) });
      if (r.ok) { const j = await r.json(); d.discordMembers = j.approximate_member_count ?? null; d.discordOnline = j.approximate_presence_count ?? null; }
    })().catch(() => {})
  ]);
  statsCache = { t: Date.now(), d };
  return d;
}
let newsCache = { t: 0, d: null };
async function news() {
  if (newsCache.d && Date.now() - newsCache.t < 60000) return newsCache.d;
  let d;
  try { d = { available: true, announcements: (await botFetch("GET", "/announcements?limit=10")).announcements }; }
  catch (e) { console.error("News failed:", e.message); d = { available: false, announcements: [] }; }
  newsCache = { t: Date.now(), d };
  return d;
}

/* ---------- routes ---------- */
async function me(req) {
  const u = await getUser(req);
  const r = await rolesFor(u.discordId);
  const { data } = await db().from("applications").select("status,created_at")
    .eq("user_id", u.user.id).order("created_at", { ascending: false }).limit(1);
  return { discordId: u.discordId, username: u.username, avatar: u.avatar, botOnline: !r.botError,
    isStaff: !!r.isStaff, isAdmin: !!r.isAdmin, canReview: !!r.canReview, canEditSite: !!r.canEditSite, canIaGuide: !!r.canIaGuide,
    roles: r.roles || [], strikes: r.strikes || 0, warnings: r.warnings || 0, blacklists: r.blacklists || [],
    application: data?.[0] || null };
}

async function apply(req) {
  const u = await getUser(req);
  const answers = cleanAnswers((await readBody(req)).answers);
  const r = await rolesFor(u.discordId);
  if (!r.botError && r.isMember === false) throw new HttpError(403, "Join our Discord server before applying");
  const { data, error } = await db().from("applications")
    .insert({ user_id: u.user.id, discord_id: u.discordId, discord_username: u.username, answers })
    .select("id").single();
  if (error) {
    if (error.code === "23505") throw new HttpError(409, "You already have a pending application");
    console.error("Insert failed:", error.message);
    throw new HttpError(500, "Could not save your application");
  }
  let notified = false;
  try {
    const b = await botFetch("POST", "/applications", {
      id: data.id, robloxUsername: answers["0-0"], discordUsername: answers["0-1"], age: answers["0-2"],
      robloxUserId: answers["0-3"], timezone: answers["0-4"], activity: answers["0-5"],
      discordId: u.discordId, reviewUrl: env.SITE_URL.replace(/\/+$/, "") + "/#staff"
    });
    await db().from("applications").update({ bot_message_id: b.messageId }).eq("id", data.id);
    notified = true;
  } catch (e) { console.error("Bot notify failed:", e.message); }
  return json({ ok: true, notified });
}

async function recordDecision(id, decision, reason, reviewerId) {
  if (!["approved", "denied"].includes(decision)) throw new HttpError(400, "Bad decision");
  const { data: app } = await db().from("applications").select("*").eq("id", id).maybeSingle();
  if (!app) throw new HttpError(404, "Application not found");
  if (app.discord_id === reviewerId) throw new HttpError(403, "You cannot review your own application");
  const { data: upd, error } = await db().from("applications")
    .update({ status: decision, reviewed_by: reviewerId, review_reason: reason || null, reviewed_at: new Date().toISOString() })
    .eq("id", id).eq("status", "pending").select("id");
  if (error) throw new HttpError(500, "Could not save the decision");
  if (!upd?.length) throw new HttpError(409, "This application was already reviewed");
  return app;
}
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
async function admin(req, method, seg) {
  const [a, id, c] = seg;
  const u = await needFlag(req, a === "guides" || a === "quota" ? "isStaff" : a === "content" ? "canEditSite" : "canReview");

  if (method === "GET" && a === "applications" && !id) {
    const { data, error } = await db().from("applications")
      .select("id,discord_id,discord_username,status,created_at,reviewed_by")
      .order("created_at", { ascending: false }).limit(100);
    if (error) throw new HttpError(500, "Could not load applications");
    return json({ applications: data });
  }
  if (a === "applications" && id) {
    if (!UUID.test(id)) throw new HttpError(400, "Bad application id");
    if (method === "GET" && !c) {
      const { data: app } = await db().from("applications").select("*").eq("id", id).maybeSingle();
      if (!app) throw new HttpError(404, "Application not found");
      const { data: notes } = await db().from("application_notes").select("*")
        .eq("application_id", id).order("created_at");
      return json({ application: app, notes: notes || [] });
    }
    if (method === "POST" && c === "notes") {
      const note = String((await readBody(req)).note || "").trim().slice(0, 2000);
      if (!note) throw new HttpError(400, "Write a note first");
      const { error } = await db().from("application_notes")
        .insert({ application_id: id, author_discord_id: u.discordId, author_name: u.username, note });
      if (error) throw new HttpError(500, "Could not save the note");
      return json({ ok: true });
    }
    if (method === "POST" && c === "decision") {
      const b = await readBody(req);
      const reason = String(b.reason || "").trim().slice(0, 1000);
      const app = await recordDecision(id, b.decision, reason, u.discordId);
      let bot = null, botError = null;
      try {
        bot = await botFetch("POST", "/applications/decision", {
          applicationId: id, messageId: app.bot_message_id || "0".repeat(17), decision: b.decision,
          applicantDiscordId: app.discord_id, reviewerDiscordId: u.discordId, reason
        });
      } catch (e) { botError = e.message; }
      return json({ ok: true, bot, botError });
    }
  }
  if (method === "POST" && a === "announcements") {
    const b = await readBody(req);
    const title = String(b.title || "").trim().slice(0, 256), message = String(b.message || "").trim().slice(0, 4000);
    if (!title || !message) throw new HttpError(400, "Title and message are required");
    try { await botFetch("POST", "/announcements", { title, message, authorDiscordId: u.discordId }); }
    catch (e) { throw new HttpError(502, "Bot could not post: " + e.message); }
    newsCache = { t: 0, d: null };
    return json({ ok: true });
  }
  if (method === "POST" && a === "content") {
    const ch = (await readBody(req)).changes;
    if (!ch || typeof ch !== "object") throw new HttpError(400, "No changes sent");
    const rows = [];
    for (const [k, v] of Object.entries(ch).slice(0, 300)) {
      if (!/^((home|about|departments|applications|news)\.\d{1,3}|dept\.\d\.(name|desc|lead|link))$/.test(k)) throw new HttpError(400, "Unknown field " + k);
      const val = String(v ?? "").trim().slice(0, 1000);
      if (!val) throw new HttpError(400, "Text cannot be empty");
      if (k.endsWith(".link") && !/^https:\/\/(discord\.gg|discord\.com\/invite)\/[A-Za-z0-9-]{2,40}$/.test(val))
        throw new HttpError(400, "Links must be Discord invites like https://discord.gg/abc");
      rows.push({ key: k, value: val, updated_by: u.discordId, updated_at: new Date().toISOString() });
    }
    if (!rows.length) throw new HttpError(400, "No changes sent");
    const { error } = await db().from("site_content").upsert(rows);
    if (error) { console.error("Content save failed:", error.message); throw new HttpError(500, "Could not save changes"); }
    return json({ ok: true });
  }
  if (method === "GET" && a === "guides") {
    const g = [];
    if (env.GUIDE_OPERATIONS_URL) g.push({ name: "Staff Operations Manual", url: env.GUIDE_OPERATIONS_URL });
    if (env.GUIDE_IA_URL && u.r.canIaGuide) g.push({ name: "Internal Affairs Handbook", url: env.GUIDE_IA_URL });
    return json({ guides: g });
  }
  if (method === "GET" && a === "quota") return json(await quotaFor(u.discordId));
  throw new HttpError(404, "Not found");
}
async function botRoute(req, seg) {
  const raw = await req.text();
  if (req.method !== "POST" || !verifyBot(req, raw)) throw new HttpError(401, "Invalid signature");
  if (seg[1] === "decision") {
    let b; try { b = JSON.parse(raw); } catch { throw new HttpError(400, "Invalid JSON"); }
    if (!UUID.test(String(b.applicationId)) || !/^\d{17,20}$/.test(String(b.reviewerDiscordId))) throw new HttpError(400, "Bad request");
    const app = await recordDecision(b.applicationId, b.decision, String(b.reason || "").slice(0, 1000), b.reviewerDiscordId);
    return json({ ok: true, applicantDiscordId: app.discord_id });
  }
  throw new HttpError(404, "Not found");
}

async function handle(req, ctx) {
  const seg = (await ctx.params).route || [];
  const path = "/" + seg.join("/"), m = req.method;
  if (m === "GET" && path === "/config") return json({ supabaseUrl: env.SUPABASE_URL, supabaseAnonKey: env.SUPABASE_ANON_KEY });
  if (m === "GET" && path === "/content") {
    const { data, error } = await db().from("site_content").select("key,value");
    if (error) console.error("Content load failed:", error.message);
    const c = {}; (data || []).forEach(r => { c[r.key] = r.value; });
    return json({ content: c });
  }
  if (m === "GET" && path === "/stats") return json(await stats());
  if (m === "GET" && path === "/news") return json(await news());
  if (m === "GET" && path === "/me") return json(await me(req));
  if (m === "POST" && path === "/apply") return apply(req);
  if (seg[0] === "admin") return admin(req, m, seg.slice(1));
  if (seg[0] === "bot") return botRoute(req, seg);
  throw new HttpError(404, "Not found");
}
async function safe(req, ctx) {
  try { return await handle(req, ctx); }
  catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    console.error("API error:", e);
    return json({ error: "Internal error" }, 500);
  }
}
export const GET = safe;
export const POST = safe;

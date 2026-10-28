// API de cuentas y progreso de PyQuest (Cloudflare Pages Functions).
// Necesita un espacio de nombres KV vinculado al proyecto con el nombre DB.
//
//   POST /api/register   {user, pass}      -> {user, token}
//   POST /api/login      {user, pass}      -> {user, token}
//   POST /api/logout                        -> {ok}
//   GET  /api/me                            -> {user}
//   GET  /api/progress                      -> {data, updatedAt}
//   PUT  /api/progress   {data, updatedAt}  -> {ok, updatedAt}

const enc = new TextEncoder();
const USER_RE = /^[a-z0-9_]{3,20}$/;
const SESSION_TTL = 60 * 60 * 24 * 180; // 180 días
const MAX_FAILS = 10;                  // intentos fallidos por usuario...
const FAIL_WINDOW = 15 * 60;           // ...cada 15 minutos
const MAX_PROGRESS_BYTES = 200 * 1024;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const sha256 = async (s) => toHex(await crypto.subtle.digest("SHA-256", enc.encode(s)));

async function hashPassword(pass, saltB64) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromB64(saltB64), iterations: 100000 },
    key,
    256
  );
  return toB64(bits);
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function newSession(env, user) {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  const token = toHex(raw);
  await env.DB.put("session:" + (await sha256(token)), user, { expirationTtl: SESSION_TTL });
  return token;
}

function bearer(request) {
  const m = (request.headers.get("authorization") || "").match(/^Bearer ([0-9a-f]{64})$/);
  return m ? m[1] : null;
}

async function currentUser(request, env) {
  const token = bearer(request);
  return token ? env.DB.get("session:" + (await sha256(token))) : null;
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function credentials(body) {
  const user = String(body?.user ?? "").trim().toLowerCase();
  const pass = String(body?.pass ?? "");
  if (!USER_RE.test(user)) return { error: "El usuario debe tener de 3 a 20 caracteres: letras minúsculas, números o _." };
  if (pass.length < 6 || pass.length > 128) return { error: "La contraseña debe tener al menos 6 caracteres." };
  return { user, pass };
}

export async function onRequest({ request, env, params }) {
  if (!env.DB) return json({ error: "Las cuentas todavía no están activadas en el servidor." }, 503);

  const route = [].concat(params.path || []).join("/");
  const method = request.method;

  try {
    if (route === "register" && method === "POST") {
      const c = credentials(await readBody(request));
      if (c.error) return json({ error: c.error }, 400);
      if (await env.DB.get("user:" + c.user)) return json({ error: "Ese nombre de usuario ya existe." }, 409);
      const salt = new Uint8Array(16);
      crypto.getRandomValues(salt);
      const saltB64 = toB64(salt);
      const record = { salt: saltB64, hash: await hashPassword(c.pass, saltB64), created: Date.now() };
      await env.DB.put("user:" + c.user, JSON.stringify(record));
      return json({ user: c.user, token: await newSession(env, c.user) }, 201);
    }

    if (route === "login" && method === "POST") {
      const c = credentials(await readBody(request));
      if (c.error) return json({ error: "Usuario o contraseña incorrectos." }, 401);
      const failKey = "fail:" + c.user;
      const fails = Number((await env.DB.get(failKey)) || 0);
      if (fails >= MAX_FAILS) return json({ error: "Demasiados intentos. Espera 15 minutos y vuelve a probar." }, 429);
      const raw = await env.DB.get("user:" + c.user);
      const record = raw ? JSON.parse(raw) : null;
      const ok = record && safeEqual(await hashPassword(c.pass, record.salt), record.hash);
      if (!ok) {
        await env.DB.put(failKey, String(fails + 1), { expirationTtl: FAIL_WINDOW });
        return json({ error: "Usuario o contraseña incorrectos." }, 401);
      }
      if (fails) await env.DB.delete(failKey);
      return json({ user: c.user, token: await newSession(env, c.user) });
    }

    if (route === "logout" && method === "POST") {
      const token = bearer(request);
      if (token) await env.DB.delete("session:" + (await sha256(token)));
      return json({ ok: true });
    }

    const user = await currentUser(request, env);
    if (!user) return json({ error: "Tu sesión ha caducado. Vuelve a entrar." }, 401);

    if (route === "me" && method === "GET") return json({ user });

    if (route === "progress" && method === "GET") {
      const raw = await env.DB.get("progress:" + user);
      return json(raw ? JSON.parse(raw) : { data: null, updatedAt: 0 });
    }

    if (route === "progress" && method === "PUT") {
      const text = await request.text();
      if (text.length > MAX_PROGRESS_BYTES) return json({ error: "El progreso es demasiado grande." }, 413);
      let body;
      try {
        body = JSON.parse(text);
      } catch {
        return json({ error: "Datos no válidos." }, 400);
      }
      if (!body || typeof body.data !== "object" || body.data === null) return json({ error: "Datos no válidos." }, 400);
      const updatedAt = Number(body.updatedAt) || Date.now();
      await env.DB.put("progress:" + user, JSON.stringify({ data: body.data, updatedAt }));
      return json({ ok: true, updatedAt });
    }

    return json({ error: "Ruta no encontrada." }, 404);
  } catch (e) {
    return json({ error: "Error del servidor. Inténtalo de nuevo." }, 500);
  }
}

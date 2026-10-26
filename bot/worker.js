// Telegram-бот с бесплатными VPN-ключами для России — Cloudflare Worker.
// Ключи берутся из подписки в вашем GitHub-репозитории (ветка sub), которая
// пересобирается каждые 3 часа, поэтому сам бот обновлять не нужно.
//
// Переменные воркера (Settings → Variables and Secrets):
//   BOT_TOKEN — токен от @BotFather (тип Secret)
//   REPO      — репозиторий с подпиской, например ivan/vpn-sub
//   CHANNEL   — необязательно: @канал, тогда в меню появится кнопка «Канал»
// После деплоя один раз откройте https://<имя-воркера>.<ваш-поддомен>.workers.dev/setup

const KEYS_PER_MESSAGE = 5;
const POOL_SIZE = 80; // из скольких лучших серверов выбирать случайные
const CACHE_MS = 10 * 60 * 1000;
const MAX_LINK_LEN = 900;

let cache = { at: 0, repo: "", data: null };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/setup") return setup(url, env);
    if (url.pathname === "/webhook" && request.method === "POST") {
      if (!env.BOT_TOKEN) return new Response("no token", { status: 500 });
      const secret = await webhookSecret(env.BOT_TOKEN);
      if (request.headers.get("X-Telegram-Bot-Api-Secret-Token") !== secret) {
        return new Response("forbidden", { status: 403 });
      }
      let update;
      try {
        update = await request.json();
      } catch {
        return new Response("bad request", { status: 400 });
      }
      ctx.waitUntil(handleUpdate(update, env).catch((e) => console.log("update error", e && e.stack)));
      return new Response("ok");
    }
    return new Response("VPN bot is running. Open /setup once after deploy.", {
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  },
};

// ---------- данные ------------------------------------------------------------------------

function repoOf(env) {
  return String(env.REPO || "").trim().replace(/^https?:\/\/github\.com\//, "").replace(/\/+$/, "");
}

function subUrls(repo) {
  return {
    main: `https://raw.githubusercontent.com/${repo}/sub/ru-vpn.txt`,
    mirror: `https://cdn.jsdelivr.net/gh/${repo}@sub/ru-vpn.txt`,
    full: `https://raw.githubusercontent.com/${repo}/sub/ru-vpn-full.txt`,
  };
}

async function loadData(env) {
  const repo = repoOf(env);
  if (cache.data && cache.repo === repo && Date.now() - cache.at < CACHE_MS) return cache.data;
  const u = subUrls(repo);
  let text = null;
  for (const src of [u.main, u.mirror]) {
    try {
      const res = await fetch(src, { cf: { cacheTtl: 600, cacheEverything: true } });
      if (res.ok) {
        text = await res.text();
        if (text.includes("://")) break;
      }
    } catch (e) {
      console.log("fetch failed", src, e && e.message);
    }
    text = null;
  }
  if (!text) {
    if (cache.data) return cache.data; // лучше старые данные, чем ничего
    throw new Error("subscription unavailable");
  }
  const data = parseSub(text);
  cache = { at: Date.now(), repo, data };
  return data;
}

function b64decodeUtf8(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

function remarkOf(link) {
  if (link.startsWith("vmess://")) {
    try {
      return JSON.parse(b64decodeUtf8(link.slice(8).split("#")[0])).ps || "";
    } catch {
      return "";
    }
  }
  const i = link.lastIndexOf("#");
  if (i < 0) return "";
  try {
    return decodeURIComponent(link.slice(i + 1));
  } catch {
    return link.slice(i + 1);
  }
}

function parseSub(text) {
  const items = [];
  let updated = "";
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith("#")) {
      if (line.startsWith("#announce: base64:")) {
        try {
          updated = b64decodeUtf8(line.slice("#announce: base64:".length)).split(" · ")[0];
        } catch {}
      }
      continue;
    }
    if (!/^(vless|vmess|trojan|ss|hysteria2|hy2|tuic):\/\//i.test(line)) continue;
    const name = remarkOf(line);
    const m = name.match(/^(\S+)\s+(.+?)\s+·\s+(ЧС|БС)\s+·\s+\d+/);
    items.push({
      link: line,
      flag: m ? m[1] : "🌐",
      proto: m ? m[2] : (line.split("://")[0] || "").toUpperCase(),
      mode: m ? m[3] : "ЧС",
    });
  }
  const bl = items.filter((x) => x.mode === "ЧС");
  const wl = items.filter((x) => x.mode === "БС");
  const byFlag = new Map();
  for (const it of items) {
    if (!byFlag.has(it.flag)) byFlag.set(it.flag, []);
    byFlag.get(it.flag).push(it);
  }
  const countries = [...byFlag.entries()]
    .filter(([f]) => f !== "🌐")
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 15)
    .map(([flag, list]) => ({ flag, count: list.length }));
  return { items, bl, wl, byFlag, countries, updated };
}

// один и тот же сервер часто встречается с разными IP — в одной выдаче показываем его только раз
function backendOf(link) {
  if (link.startsWith("vmess://")) {
    try {
      const o = JSON.parse(b64decodeUtf8(link.slice(8).split("#")[0]));
      return "vmess:" + o.id + ":" + (o.host || o.sni || o.add);
    } catch {
      return link;
    }
  }
  return link.split("@")[0];
}

function pick(list, n) {
  const pool = list.filter((x) => x.link.length <= MAX_LINK_LEN).slice(0, Math.max(n, POOL_SIZE));
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  const seen = new Set();
  const out = [];
  for (const it of pool) {
    const b = backendOf(it.link);
    if (seen.has(b)) continue;
    seen.add(b);
    out.push(it);
    if (out.length === n) break;
  }
  return out;
}

// ---------- Telegram ------------------------------------------------------------------------

async function tg(env, method, payload) {
  const res = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const j = await res.json().catch(() => ({ ok: false, description: "bad json" }));
  if (!j.ok) console.log("telegram", method, j.description);
  return j;
}

const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

function send(env, chatId, text, keyboard) {
  const payload = { chat_id: chatId, text, parse_mode: "HTML", link_preview_options: { is_disabled: true } };
  if (keyboard) payload.reply_markup = { inline_keyboard: keyboard };
  return tg(env, "sendMessage", payload);
}

function menuKeyboard(env) {
  const kb = [
    [{ text: "⚡ Ключи", callback_data: "keys" }, { text: "📶 Белые списки", callback_data: "wl" }],
    [{ text: "🔗 Подписка", callback_data: "sub" }, { text: "🌍 Страны", callback_data: "countries" }],
    [{ text: "📲 Как подключить", callback_data: "help" }],
  ];
  const ch = String(env.CHANNEL || "").trim().replace(/^@/, "").replace(/^https?:\/\/t\.me\//, "");
  if (ch) kb.push([{ text: "📢 Канал", url: `https://t.me/${ch}` }]);
  return kb;
}

const backRow = [{ text: "🏠 Меню", callback_data: "menu" }];

async function handleUpdate(update, env) {
  if (update.callback_query) {
    const q = update.callback_query;
    await tg(env, "answerCallbackQuery", { callback_query_id: q.id });
    if (!q.message || q.message.chat.type !== "private") return;
    return route(env, q.message.chat.id, String(q.data || ""));
  }
  const msg = update.message;
  if (!msg || !msg.chat || msg.chat.type !== "private") return;
  const text = String(msg.text || "").trim();
  const cmd = text.startsWith("/") ? text.split(/[\s@]/)[0].slice(1).toLowerCase() : "";
  const map = { start: "menu", menu: "menu", keys: "keys", wl: "wl", sub: "sub", countries: "countries", help: "help" };
  return route(env, msg.chat.id, map[cmd] || "menu");
}

async function route(env, chatId, action) {
  let data = null;
  try {
    data = await loadData(env);
  } catch (e) {
    console.log("data error", e && e.message);
  }
  const needsData = action === "keys" || action === "wl" || action === "countries" || action.startsWith("c:");
  if (needsData && !data) {
    return send(env, chatId, "😔 Список серверов сейчас недоступен. Попробуй через пару минут или возьми подписку.", [
      [{ text: "🔗 Подписка", callback_data: "sub" }, ...backRow],
    ]);
  }
  if (action === "keys") return sendKeys(env, chatId, data.bl, "⚡ <b>Ключи для обычного интернета</b>", "keys", data);
  if (action === "wl") {
    return sendKeys(env, chatId, data.wl,
      "📶 <b>Ключи для белых списков</b>\nДля мобильного интернета, когда открываются только разрешённые сайты.", "wl", data);
  }
  if (action.startsWith("c:")) {
    const flag = action.slice(2);
    return sendKeys(env, chatId, data.byFlag.get(flag) || [], `${flag} <b>Ключи по стране</b>`, action, data);
  }
  if (action === "countries") {
    const rows = [];
    let row = [];
    for (const c of data.countries) {
      row.push({ text: `${c.flag} ${c.count}`, callback_data: `c:${c.flag}` });
      if (row.length === 3) {
        rows.push(row);
        row = [];
      }
    }
    if (row.length) rows.push(row);
    rows.push(backRow);
    return send(env, chatId, "🌍 <b>Выбери страну</b>\nЦифра — сколько серверов сейчас в базе.", rows);
  }
  if (action === "sub" || action === "qr") {
    const repo = repoOf(env);
    const u = subUrls(repo);
    if (action === "qr") {
      const qr = `https://api.qrserver.com/v1/create-qr-code/?size=600x600&margin=12&data=${encodeURIComponent(u.main)}`;
      const r = await tg(env, "sendPhoto", { chat_id: chatId, photo: qr, caption: "Отсканируй в приложении: «+» → «QR-код»." });
      if (r.ok) return;
    }
    return send(
      env,
      chatId,
      "🔗 <b>Подписка: все серверы в одной ссылке</b>\n" +
        "Скопируй ссылку и добавь её в приложение как подписку (Happ, v2RayTun, Hiddify, v2rayNG: «+» → «Импорт из буфера»). " +
        "Приложение будет само подтягивать свежие сервера.\n\n" +
        `Основная (${data ? data.items.length : "~1500"} серверов):\n<code>${esc(u.main)}</code>\n\n` +
        `Если не открывается:\n<code>${esc(u.mirror)}</code>\n\n` +
        `Полная (очень большая, для компьютера):\n<code>${esc(u.full)}</code>`,
      [[{ text: "📷 QR-код", callback_data: "qr" }], backRow],
    );
  }
  if (action === "help") {
    return send(
      env,
      chatId,
      "📲 <b>Как подключиться</b>\n\n" +
        "1. Установи приложение: <b>Happ</b> или <b>v2RayTun</b> (iPhone и Android), <b>Hiddify</b> или <b>v2rayNG</b> (Android), <b>Hiddify</b> или <b>v2rayN</b> (компьютер).\n" +
        "2. Возьми <b>подписку</b> (лучший вариант) или несколько ключей и скопируй.\n" +
        "3. В приложении: «+» → «Импорт из буфера».\n" +
        "4. Запусти проверку пинга и подключись к серверу с наименьшей задержкой.\n\n" +
        "Не подключается? Обнови подписку, а если мобильный интернет в режиме белых списков, бери ключи «📶 Белые списки».\n\n" +
        "⚠️ Это публичные бесплатные серверы неизвестных владельцев. Не открывай через них банк и важные аккаунты.",
      [backRow],
    );
  }
  // меню
  return send(
    env,
    chatId,
    "👋 <b>Бесплатный VPN для России</b>\n\n" +
      "Свежие бесплатные ключи (VLESS, Trojan, Hysteria2) из открытых источников, список обновляется каждые 3 часа.\n\n" +
      "• <b>Ключи</b>: несколько серверов, чтобы быстро подключиться\n" +
      "• <b>Подписка</b>: одна ссылка со всеми серверами, лучший вариант\n" +
      "• <b>Белые списки</b>: для мобильного интернета с ограничениями\n\n" +
      (data ? `Сейчас в базе: <b>${data.items.length}</b> серверов${data.updated ? ` · ${esc(data.updated)}` : ""}.` : ""),
    menuKeyboard(env),
  );
}

async function sendKeys(env, chatId, list, title, again, data) {
  const chosen = pick(list, KEYS_PER_MESSAGE);
  if (!chosen.length) return send(env, chatId, "Таких серверов сейчас нет, попробуй другие.", [backRow]);
  let text = `${title}\nНажми на ключ, чтобы скопировать, затем в приложении: «+» → «Импорт из буфера».\n`;
  chosen.forEach((it, i) => {
    const part = `\n${i + 1}. ${it.flag} ${esc(it.proto)} · ${it.mode}\n<code>${esc(it.link)}</code>\n`;
    if (text.length + part.length < 3800) text += part;
  });
  if (data && data.updated) text += `\n<i>${esc(data.updated)}</i>`;
  return send(env, chatId, text, [[{ text: "🔄 Ещё", callback_data: again }, ...backRow]]);
}

// ---------- первичная настройка -----------------------------------------------------------

async function webhookSecret(token) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("vpn-bot:" + token));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 48);
}

async function setup(url, env) {
  const out = [];
  const reply = () => new Response(out.join("\n") + "\n", { headers: { "content-type": "text/plain; charset=utf-8" } });
  if (!env.BOT_TOKEN) {
    out.push("❌ Нет переменной BOT_TOKEN. Добавьте её в Settings → Variables and Secrets (тип Secret) и нажмите Deploy.");
    return reply();
  }
  if (!repoOf(env)) {
    out.push("❌ Нет переменной REPO (например ivan/vpn-sub). Добавьте её в Settings → Variables and Secrets.");
    return reply();
  }
  const me = await tg(env, "getMe", {});
  if (!me.ok) {
    out.push("❌ Telegram не принял токен: " + (me.description || "неизвестная ошибка") + ". Проверьте BOT_TOKEN.");
    return reply();
  }
  const hook = `${url.origin}/webhook`;
  const wh = await tg(env, "setWebhook", {
    url: hook,
    secret_token: await webhookSecret(env.BOT_TOKEN),
    allowed_updates: ["message", "callback_query"],
    drop_pending_updates: true,
  });
  out.push(wh.ok ? `✅ Вебхук установлен: ${hook}` : "❌ Вебхук: " + wh.description);
  await tg(env, "setMyCommands", {
    commands: [
      { command: "start", description: "Меню" },
      { command: "keys", description: "Ключи для обычного интернета" },
      { command: "wl", description: "Ключи для белых списков" },
      { command: "sub", description: "Ссылка-подписка" },
      { command: "countries", description: "Ключи по странам" },
      { command: "help", description: "Как подключить" },
    ],
  });
  await tg(env, "setMyShortDescription", { short_description: "Бесплатные VPN-ключи для России, обновляются каждые 3 часа" });
  await tg(env, "setMyDescription", {
    description:
      "Свежие бесплатные ключи VLESS, Trojan и Hysteria2 из открытых источников: для обычного интернета и для белых списков. " +
      "Нажми «Старт», чтобы получить ключи или ссылку-подписку.",
  });
  out.push("✅ Команды и описание бота обновлены");
  cache = { at: 0, repo: "", data: null };
  try {
    const data = await loadData(env);
    out.push(`✅ Подписка найдена: ${data.items.length} серверов (ЧС ${data.bl.length}, БС ${data.wl.length})` +
      (data.updated ? ` · ${data.updated}` : ""));
  } catch (e) {
    out.push(`❌ Не удалось скачать подписку ${subUrls(repoOf(env)).main} — проверьте REPO и что в репозитории уже есть ветка sub.`);
  }
  out.push(`\nГотово. Напишите боту @${me.result.username} команду /start`);
  return reply();
}

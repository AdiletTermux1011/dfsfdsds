"use strict";
const { Telegraf } = require('telegraf');
const { promises: fs } = require('fs');
const path = require('path');
const crypto = require('crypto');

// Load .env manually (no extra dependencies)
try {
  const env = require('fs').readFileSync(path.join(__dirname, '.env'), 'utf8');
  for (const line of env.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  }
} catch {}

const ADMIN_ID = String(process.env.TELEGRAM_ADMIN_ID || '1037245138');
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const DATA_DIR = path.join(__dirname, 'data');
const ACCOUNTS_FILE = path.join(DATA_DIR, 'accounts.json');
const MAFILES_DIR = path.join(DATA_DIR, 'mafiles');

// --- Steam TOTP (manual implementation) ---
function normalizeBase32(s) {
  // Steam uses a custom Base32 alphabet; normalize to standard RFC4648
  let up = s.toUpperCase();
  up = up.replace(/0/g, 'O').replace(/1/g, 'I').replace(/8/g, 'B').replace(/9/g, 'S');
  up = up.replace(/[^A-Z2-7]/g, '');
  return up;
}

function base32Decode(s) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, index = 0;
  const out = [];
  for (let i = 0; i < s.length; i++) {
    const idx = alphabet.indexOf(s[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xFF);
    }
  }
  return Buffer.from(out);
}

function steamTime() {
  return Math.floor(Date.now() / 1000);
}

function generateSteamCode(secretB32) {
  const secret = normalizeBase32(secretB32);
  const key = base32Decode(secret);
  const counter = Math.floor(steamTime() / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter), 0);
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0F;
  const code =
    ((hmac[offset] & 0x7F) << 24) |
    ((hmac[offset + 1] & 0xFF) << 16) |
    ((hmac[offset + 2] & 0xFF) << 8) |
    (hmac[offset + 3] & 0xFF);
  return String(code % 1000000).padStart(6, '0');
}

function timeLeft() {
  return 30 - (Math.floor(Date.now() / 1000) % 30);
}

// --- Storage ---
async function ensureDirs() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.mkdir(MAFILES_DIR, { recursive: true });
}

async function loadAccounts() {
  try {
    const raw = await fs.readFile(ACCOUNTS_FILE, 'utf8');
    return JSON.parse(raw).accounts || {};
  } catch { return {}; }
}

async function saveAccounts(accounts) {
  await ensureDirs();
  await fs.writeFile(ACCOUNTS_FILE, JSON.stringify({ accounts }, null, 2), 'utf8');
}

// --- Bot ---
const bot = new Telegraf(BOT_TOKEN);

bot.use((ctx, next) => {
  if (String(ctx.from?.id) !== ADMIN_ID) {
    return ctx.reply('Доступ запрещён.');
  }
  return next();
});

bot.start((ctx) => {
  ctx.reply(
    `Привет! Я бот для генерации кодов Steam Guard.\n\n` +
    `Отправь мне .maFile — я сохраню его и буду выдавать свежие коды подтверждения.\n\n` +
    `Команды:\n/add — добавить .maFile\n/code — получить код\n/accounts — список\n/remove — удалить`
  );
});

bot.command('add', (ctx) => {
  ctx.reply('Отправь .maFile (файл).');
});

bot.on('document', async (ctx, next) => {
  const doc = ctx.message.document;
  if (doc.file_name && doc.file_name.endsWith('.maFile')) {
    try {
      const file = await bot.telegram.getFile(doc.file_id);
      const url = `https://api.telegram.org/file/bot${BOT_TOKEN}/${file.file_path}`;
      const res = await fetch(url);
      const buf = Buffer.from(await res.arrayBuffer());
      const data = JSON.parse(buf.toString('utf8'));
      if (!data.shared_secret) {
        return ctx.reply('Это не .maFile или он повреждён.');
      }
      const name = data.account_name || 'account_' + Date.now();
      const id = crypto.randomBytes(4).toString('hex');
      const filePath = path.join(MAFILES_DIR, id + '.maFile');
      await fs.writeFile(filePath, buf, 'utf8');
      const accounts = await loadAccounts();
      accounts[id] = {
        id, name,
        steamId: data.Session?.SteamID || null,
        serial: data.serial_number,
        sharedSecret: data.shared_secret,
        revocationCode: data.revocation_code,
        filePath,
        addedAt: new Date().toISOString(),
      };
      await saveAccounts(accounts);
      return ctx.reply('✅ Добавлен: ' + name + '\nID: ' + id);
    } catch (err) {
      return ctx.reply('Ошибка: ' + err.message);
    }
  }
  return next();
});

bot.command('code', async (ctx) => {
  const accounts = await loadAccounts();
  const ids = Object.keys(accounts);
  if (!ids.length) return ctx.reply('Нет аккаунтов. Используй /add.');
  const parts = ctx.message.text.split(' ');
  const id = parts[1];
  let target;
  if (id) {
    target = accounts[id];
    if (!target) return ctx.reply('Аккаунт с ID ' + id + ' не найден.');
  } else {
    target = accounts[ids[0]];
  }
  const code = generateSteamCode(target.sharedSecret);
  const left = timeLeft();
  ctx.reply(
    '🔐 Код для ' + target.name + ' (' + (target.steamId || '—') + '):\n\n' +
    code + '\n\nОбновится через ' + left + 'с.'
  );
});

bot.command('accounts', async (ctx) => {
  const accounts = await loadAccounts();
  const ids = Object.keys(accounts);
  if (!ids.length) return ctx.reply('Нет аккаунтов.');
  let msg = '📋 Аккаунты:\n\n';
  for (const id of ids) {
    const a = accounts[id];
    msg += a.name + ' — ID: ' + a.id + '\n';
  }
  ctx.reply(msg);
});

bot.command('remove', async (ctx) => {
  const parts = ctx.message.text.split(' ');
  const id = parts[1];
  if (!id) return ctx.reply('Укажи ID: /remove <id>');
  const accounts = await loadAccounts();
  if (!accounts[id]) return ctx.reply('Не найден.');
  try { await fs.unlink(accounts[id].filePath); } catch {}
  delete accounts[id];
  await saveAccounts(accounts);
  ctx.reply('🗑 Удалён.');
});

// Delete any active webhook to avoid 409 Conflict with polling
bot.telegram.deleteWebhook({ drop_pending_updates: true }).catch(() => {});

bot.launch();
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));

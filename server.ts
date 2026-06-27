import fs from 'fs';
import axios from 'axios';
import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import { initBot } from './telegram.ts';
import { google } from 'googleapis';
import { MongoClient, ObjectId } from 'mongodb';
import multer from 'multer';
import NodeCache from 'node-cache';
const driveCache = new NodeCache({ stdTTL: 60, checkperiod: 120 }); // 60s cache for drive listings

function invalidateDriveCache(accountId: string) {
  const keys = driveCache.keys();
  const toDelete = keys.filter(k => k.includes(accountId));
  if (toDelete.length > 0) driveCache.del(toDelete);
}

import { customAlphabet } from 'nanoid';
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 10;
import stream from 'stream';
import dotenv from 'dotenv';

import { TelegramClient } from 'telegram';
import { StringSession } from 'telegram/sessions/index.js';
import { Api } from 'telegram/tl/index.js';

import { Client, LargeFileUploadTask } from '@microsoft/microsoft-graph-client';
import 'isomorphic-fetch';

dotenv.config();

const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID;
const MICROSOFT_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET;
const MICROSOFT_REDIRECT_URI = `${process.env.APP_URL}/auth/microsoft/callback`;

const API_ID = Number(process.env.TELEGRAM_API_ID);
const API_HASH = process.env.TELEGRAM_API_HASH;

// ─── GramJS peer resolver ────────────────────────────────────────────────────
const resolvePeer = async (telegram: TelegramClient, id: string): Promise<any> => {
  if (!id || id === 'me') return 'me';
  const cleanId = id.trim();
  try {
    return await telegram.getEntity(cleanId);
  } catch (err: any) {
    if (/^-?\d+$/.test(cleanId)) {
      try {
        if (cleanId.startsWith('-100')) {
          return new Api.InputPeerChannel({
            channelId: BigInt(cleanId.substring(4)) as any,
            accessHash: BigInt(0) as any,
          });
        }
        if (cleanId.startsWith('-')) return new Api.InputPeerChat({ chatId: BigInt(cleanId.substring(1)) as any });
        return BigInt(cleanId) as any;
      } catch {
        throw err;
      }
    }
    throw err;
  }
};

const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
const nanoid12 = customAlphabet(alphabet, 12);
const nanoid6  = customAlphabet(alphabet, 6);
const nanoid32 = customAlphabet(alphabet, 32);
const nanoid   = (length = 12) => {
  if (length === 6) return nanoid6();
  if (length === 32) return nanoid32();
  return nanoid12();
};

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }, // 2 GB
});

// ─── GramJS singleton (bot-auth) ─────────────────────────────────────────────
let tgClient: TelegramClient | null = null;
async function getTgClient() {
  if (tgClient && tgClient.connected) return tgClient;

  const token = process.env.TELEGRAM_BOT_TOKEN;
  if (!token || token === 'YOUR_BOT_TOKEN') throw new Error('TELEGRAM_BOT_TOKEN missing');
  if (!API_ID || !API_HASH) throw new Error('TELEGRAM_API_ID / TELEGRAM_API_HASH missing');

  let sessionString = '';
  const sessionKey = `tg_session_${Buffer.from(token).toString('base64').slice(0, 16)}`;
  try {
    const database = await connectToMongo();
    const saved = await database.collection('config').findOne({ key: sessionKey });
    if (saved?.value) sessionString = saved.value;
  } catch { /* ignore */ }

  const startInstance = async (session: string) => {
    const c = new TelegramClient(new StringSession(session), API_ID, API_HASH, { connectionRetries: 5 });
    await c.start({ botToken: token, botAuthToken: token } as any);
    return c;
  };

  try {
    tgClient = await startInstance(sessionString);
  } catch (err: any) {
    if (err.message.includes('AUTH_KEY_UNREGISTERED') || err.message.includes('BotToken') || sessionString) {
      try { const db = await connectToMongo(); await db.collection('config').deleteOne({ key: sessionKey }); } catch { /* ignore */ }
      tgClient = await startInstance('');
    } else { throw err; }
  }

  if (tgClient?.session) {
    try {
      const ns = tgClient.session.save() as unknown as string;
      if (ns && ns !== sessionString) {
        const db = await connectToMongo();
        await db.collection('config').updateOne({ key: sessionKey }, { $set: { value: ns, updatedAt: new Date() } }, { upsert: true });
      }
    } catch { /* ignore */ }
  }
  return tgClient;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const PORT       = process.env.PORT || 3000;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password';
const AUTH_TOKEN     = Buffer.from(`${ADMIN_USERNAME}:${ADMIN_PASSWORD}`).toString('base64');

// ─── MongoDB ─────────────────────────────────────────────────────────────────
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const client   = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 5000, connectTimeoutMS: 5000 });
let db: any;
let isConnected = false;

async function connectToMongo() {
  if (isConnected && db) {
    try { await db.command({ ping: 1 }); return db; } catch { isConnected = false; }
  }
  try {
    await client.connect();
    db = client.db('cloudyte');
    isConnected = true;
    try {
      await db.collection('sessions').createIndex({ token: 1 }, { unique: true });
      await db.collection('sessions').createIndex({ createdAt: 1 }, { expireAfterSeconds: 2592000 });
      await db.collection('accounts').createIndex({ userId: 1 });
      await db.collection('accounts').createIndex({ email: 1 });
      await db.collection('users').createIndex({ username: 1 }, { unique: true, sparse: true });
      await db.collection('users').createIndex({ tgIds: 1 });
      await db.collection('settings').createIndex({ key: 1 }, { unique: true });
      
      // TG Drive collections
      await db.collection('tg_files').createIndex({ accountId: 1, folder: 1 });
      await db.collection('tg_files').createIndex({ accountId: 1, messageId: 1 });
      await db.collection('tg_files').createIndex({ userId: 1 });
      await db.collection('tg_files').createIndex({ shareId: 1 }, { unique: true, sparse: true });
      await db.collection('tg_files').createIndex({ name: 'text' });
      await db.collection('tg_folders').createIndex({ accountId: 1, path: 1 });
      await db.collection('tg_folders').createIndex({ userId: 1 });
    } catch { /* indexes already exist */ }

    await runMigration(db);
    await checkAdmin(db);
    
    return db;
  } catch (err) {
    console.error('MongoDB error:', err);
    throw err;
  }
}

async function runMigration(database: any) {
  const users = await database.collection('users').find({ tgId: { $exists: true }, userId: { $exists: false } }).toArray();
  if (users.length === 0) return;

  console.log(`[Migration] Starting migration for ${users.length} users...`);

  for (const oldUser of users) {
    const tgId = String(oldUser.tgId);
    
    // Check if this user was already migrated (idempotency)
    const existing = await database.collection('users').findOne({ tgIds: tgId });
    if (existing) {
      // Re-point related collections if they haven't been re-pointed
      await database.collection('accounts').updateMany({ tgId: tgId }, { $set: { userId: existing._id }, $unset: { tgId: "" } });
      await database.collection('sessions').updateMany({ tgId: tgId }, { $set: { userId: existing._id }, $unset: { tgId: "" } });
      await database.collection('tg_files').updateMany({ tgId: tgId }, { $set: { userId: existing._id }, $unset: { tgId: "" } });
      await database.collection('tg_folders').updateMany({ tgId: tgId }, { $set: { userId: existing._id }, $unset: { tgId: "" } });
      
      await database.collection('users').deleteOne({ _id: oldUser._id });
      continue;
    }

    let targetUsername = oldUser.username || `user_${tgId}`;
    // Check for username collision in NEW format users
    const usernameConflict = await database.collection('users').findOne({ username: targetUsername });
    if (usernameConflict) {
      targetUsername = `${targetUsername}_${tgId}`;
    }

    const userId = nanoid();
    try {
      await database.collection('users').insertOne({
        _id: userId as any,
        username: targetUsername,
        password: oldUser.password || '',
        tgIds: [tgId],
        isAdmin: !!oldUser.isAdmin,
        isActive: true,
        createdAt: oldUser.createdAt || new Date(),
        createdVia: 'migration',
        backupEnabled: !!oldUser.backupEnabled,
        backupAccId: oldUser.backupAccId || null
      });

      await database.collection('accounts').updateMany({ tgId: tgId }, { $set: { userId: userId }, $unset: { tgId: "" } });
      await database.collection('sessions').updateMany({ tgId: tgId }, { $set: { userId: userId }, $unset: { tgId: "" } });
      await database.collection('tg_files').updateMany({ tgId: tgId }, { $set: { userId: userId }, $unset: { tgId: "" } });
      await database.collection('tg_folders').updateMany({ tgId: tgId }, { $set: { userId: userId }, $unset: { tgId: "" } });
      await database.collection('users').deleteOne({ _id: oldUser._id });
    } catch (e) {
      console.error(`[Migration] Failed to migrate user ${tgId}:`, e);
    }
  }
  console.log('[Migration] Migration step finished.');
}

async function checkAdmin(database: any) {
  const adminUsername = process.env.ADMIN_USERNAME;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (adminUsername && adminPassword) {
    const userWithAdminName = await database.collection('users').findOne({ username: adminUsername });
    if (userWithAdminName) {
      if (!userWithAdminName.isAdmin) {
        console.log(`[Admin] Elevating existing user ${adminUsername} to Admin...`);
        await database.collection('users').updateOne({ _id: userWithAdminName._id }, { $set: { isAdmin: true } });
      }
    } else {
      console.log(`[Admin] Creating default admin: ${adminUsername}`);
      const hashedPassword = await bcrypt.hash(adminPassword, SALT_ROUNDS);
      try {
        await database.collection('users').insertOne({
          _id: nanoid() as any,
          username: adminUsername,
          password: hashedPassword,
          tgIds: [],
          isAdmin: true,
          isActive: true,
          createdAt: new Date(),
          createdVia: 'system'
        });
      } catch (e: any) {
        if (e.code !== 11000) console.error('[Admin] Error creating admin:', e);
      }
    }
  }
}

async function ensureDefaultSettings(database: any) {
  const settings = [
    { key: 'registrationEnabled', value: true },
    { key: 'webRegistrationEnabled', value: true },
    { key: 'botRegistrationEnabled', value: true }
  ];

  for (const s of settings) {
    await database.collection('settings').updateOne(
      { key: s.key },
      { $setOnInsert: s },
      { upsert: true }
    );
  }
}

async function getUserIdByTg(tgId: number | string, database: any) {
  const user = await database.collection('users').findOne({ tgIds: String(tgId) });
  if (!user || !user.isActive) return null;
  return user._id;
}
const requireAuth = async (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  const tokenFromQuery = req.query.token;
  const database   = await connectToMongo();
  req.db = database;
  
  if (authHeader === `Basic ${AUTH_TOKEN}`) { 
    req.isAdmin = true; 
    return next(); 
  }
  
  const token = authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : tokenFromQuery;
  if (token) {
    const session = await database.collection('sessions').findOne({ token });
    if (session) {
      const user = await database.collection('users').findOne({ _id: session.userId });
      if (user && user.isActive) {
        req.userId  = user._id;
        req.isAdmin = !!user.isAdmin;
        req.user    = user;
        return next();
      }
    }
  }
  res.status(401).json({ error: 'Unauthorized' });
};

// ─── Cloud clients ────────────────────────────────────────────────────────────
async function getDriveClient(tokens: any) {
  const auth = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
  auth.setCredentials(tokens);
  return google.drive({ version: 'v3', auth });
}

async function getOneDriveClient(tokens: any, accountId?: string) {
  if (!tokens.expiry_date && tokens.expires_in)
    tokens = { ...tokens, expiry_date: Date.now() + Number(tokens.expires_in) * 1000 };

  const c = Client.init({
    authProvider: async (done) => {
      try {
        const isExpired = !tokens.expiry_date || Date.now() > tokens.expiry_date - 300000;
        if (isExpired && tokens.refresh_token) {
          const r = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
            new URLSearchParams({
              client_id: MICROSOFT_CLIENT_ID!, client_secret: MICROSOFT_CLIENT_SECRET!,
              grant_type: 'refresh_token', refresh_token: tokens.refresh_token,
            }));
          tokens = { ...tokens, access_token: r.data.access_token, refresh_token: r.data.refresh_token || tokens.refresh_token,
            expires_in: r.data.expires_in, expiry_date: Date.now() + Number(r.data.expires_in) * 1000 };
          if (accountId) {
            const d = await connectToMongo();
            await d.collection('accounts').updateOne({ _id: new ObjectId(accountId) }, { $set: { tokens } });
          }
          done(null, tokens.access_token);
        } else { done(null, tokens.access_token); }
      } catch (err: any) { done(err, null); }
    },
  });
  return c;
}

// ─── TG Drive helpers ─────────────────────────────────────────────────────────
// Upload a buffer to a Telegram channel via GramJS, save metadata, return record.
async function tgUploadFile(
  accountId: string, channelId: string, buf: Buffer,
  fileName: string, mimeType: string, folder: string, caption = ''
) {
  const database = await connectToMongo();
  const tmpPath  = path.join('/tmp', `tgu_${Date.now()}_${fileName.replace(/[^a-zA-Z0-9._-]/g, '_')}`);
  fs.writeFileSync(tmpPath, buf);
  try {
    const telegram   = await getTgClient();
    const peerEntity = await resolvePeer(telegram, channelId);
    const result     = await telegram.sendFile(peerEntity, {
      file: tmpPath,
      caption,
      forceDocument: true,
      attributes: [new Api.DocumentAttributeFilename({ fileName })],
    }) as any;
    const messageId = result.id as number;
    const shareId   = nanoid(6);
    const record    = {
      accountId: new ObjectId(accountId),
      messageId,
      shareId,
      name:     fileName,
      size:     buf.length,
      mimeType,
      folder,
      caption,
      date:     Math.floor(Date.now() / 1000),
    };
    await database.collection('tg_files').insertOne(record);
    return record;
  } finally {
    if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
  }
}

// Stream a TG file to an HTTP response (supports Range headers for video/audio).
async function tgStreamFile(messageId: number, channelId: string, req: any, res: any, meta: any) {
  const telegram = await getTgClient();
  const peer     = await resolvePeer(telegram, channelId);
  const messages = await telegram.getMessages(peer, { ids: [messageId] });
  if (!messages || !messages[0] || !messages[0].media) throw new Error('Message not found');
  const media    = messages[0].media as any;

  // Try to get total size from media document
  let totalSize: number = meta?.size || 0;
  if (!totalSize && media?.document?.size) totalSize = Number(media.document.size);

  const rangeHeader = req.headers['range'];
  if (rangeHeader && totalSize) {
    const [startStr, endStr] = rangeHeader.replace(/bytes=/, '').split('-');
    const start = parseInt(startStr, 10);
    const end   = endStr ? parseInt(endStr, 10) : totalSize - 1;
    const chunkSize = end - start + 1;
    res.writeHead(206, {
      'Content-Range':  `bytes ${start}-${end}/${totalSize}`,
      'Accept-Ranges':  'bytes',
      'Content-Length': chunkSize,
      'Content-Type':   meta?.mimeType || 'application/octet-stream',
    });
    let downloaded = 0;
    for await (const chunk of telegram.iterDownload({ file: media, requestSize: 512 * 1024, offset: BigInt(start) as any })) {
      downloaded += chunk.length;
      res.write(chunk);
      if (downloaded >= chunkSize) break;
    }
    res.end();
  } else {
    res.setHeader('Content-Type', meta?.mimeType || 'application/octet-stream');
    if (totalSize) res.setHeader('Content-Length', totalSize);
    for await (const chunk of telegram.iterDownload({ file: media, requestSize: 512 * 1024 })) {
      res.write(chunk);
    }
    res.end();
  }
}

// Normalise a raw tg_files doc to the standard file shape the frontend expects.
function normaliseTgFile(f: any) {
  const mime = f.mimeType || '';
  let type   = 'other';
  if (mime.includes('image'))        type = 'image';
  else if (mime.includes('video'))   type = 'video';
  else if (mime.includes('audio'))   type = 'audio';
  else if (mime.includes('pdf'))     type = 'pdf';
  else if (mime.includes('zip') || mime.includes('rar') || mime.includes('7z')) type = 'zip';
  else if (mime.includes('spreadsheet') || mime.includes('excel')) type = 'sheet';
  else if (mime.includes('document') || mime.includes('word'))     type = 'doc';
  else if (mime.includes('presentation') || mime.includes('powerpoint')) type = 'slide';
  return {
    id:         String(f._id),
    messageId:  f.messageId,
    name:       f.name,
    type,
    mimeType:   f.mimeType,
    size:       f.size ? (Number(f.size) / (1024 ** 2)).toFixed(1) + ' MB' : '-',
    sizeBytes:  f.size,
    modified:   f.date ? new Date(f.date * 1000).toLocaleDateString() : '-',
    createdAt:  f.date ? new Date(f.date * 1000).toLocaleDateString() : '-',
    folder:     f.folder || '',
    shareId:    f.shareId,
    isTgDrive:  true,
  };
}

// ─── Express app ─────────────────────────────────────────────────────────────
export const app = express();
app.use(express.json());

// ─── Auth routes ─────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  
  const database = await connectToMongo();
  const globalReg = await database.collection('settings').findOne({ key: 'registrationEnabled' });
  const webReg    = await database.collection('settings').findOne({ key: 'webRegistrationEnabled' });
  
  if (globalReg?.value === false || webReg?.value === false) {
    return res.status(403).json({ error: 'Registration is currently disabled.' });
  }

  const existing = await database.collection('users').findOne({ username });
  if (existing) return res.status(400).json({ error: 'Username already taken' });

  try {
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    await database.collection('users').insertOne({
      _id: nanoid() as any,
      username,
      password: hashedPassword,
      tgIds: [],
      isAdmin: false,
      isActive: true,
      createdAt: new Date(),
      createdVia: 'web'
    });
    res.json({ success: true });
  } catch (err: any) {
    if (err.code === 11000) return res.status(400).json({ error: 'Username already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/public/settings', async (req, res) => {
  const db = await connectToMongo();
  const settings = await db.collection('settings').find({}).toArray();
  const publicSettings: any = {};
  settings.forEach((s: any) => {
    if (s.key === 'registrationEnabled' || s.key === 'webRegistrationEnabled' || s.key === 'botRegistrationEnabled') {
      publicSettings[s.key] = s.value;
    }
  });
  res.json(publicSettings);
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const database = await connectToMongo();
  
  const user = await database.collection('users').findOne({ username });
  if (!user || !user.isActive) return res.status(401).json({ error: 'Invalid credentials or account disabled' });
  
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });
  
  const sessionToken = nanoid(32);
  await database.collection('sessions').insertOne({ 
    token: sessionToken, 
    userId: user._id, 
    username: user.username, 
    createdAt: new Date() 
  });
  
  res.json({ success: true, token: sessionToken, username: user.username, isAdmin: !!user.isAdmin });
});

app.get('/api/admin/stats', requireAuth, async (req: any, res: any) => {
  if (!req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  const db = req.db;
  const stats = {
    totalUsers: await db.collection('users').countDocuments(),
    totalAccounts: await db.collection('accounts').countDocuments(),
    totalFiles: (await db.collection('tg_files').countDocuments()) + 
                 // We don't easily know GDrive/OneDrive total files without crawling, 
                 // but we can show indexed files if we had them.
                 0
  };
  res.json(stats);
});

app.get('/api/admin/users', requireAuth, async (req: any, res: any) => {
  if (!req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  const db = req.db;
  
  const users = await db.collection('users').find({}).sort({ createdAt: -1 }).toArray();
  const accounts = await db.collection('accounts').aggregate([
    { $group: { _id: "$userId", count: { $sum: 1 } } }
  ]).toArray();

  const accountMap = new Map(accounts.map(a => [a._id, a.count]));

  const result = users.map(u => ({
    id: u._id,
    username: u.username,
    isActive: u.isActive !== false,
    isAdmin: !!u.isAdmin,
    createdAt: u.createdAt,
    accountCount: accountMap.get(u._id) || 0
  }));

  res.json(result);
});

app.post('/api/admin/users/:id/toggle', requireAuth, async (req: any, res: any) => {
  if (!req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  const db = req.db;
  const user = await db.collection('users').findOne({ _id: req.params.id });
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.isAdmin) return res.status(400).json({ error: 'Cannot disable admin' });
  
  await db.collection('users').updateOne({ _id: req.params.id }, { $set: { isActive: !user.isActive } });
  res.json({ success: true, isActive: !user.isActive });
});

app.delete('/api/admin/users/:id', requireAuth, async (req: any, res: any) => {
  if (!req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  const db = req.db;
  const user = await db.collection('users').findOne({ _id: req.params.id });
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.isAdmin) return res.status(400).json({ error: 'Cannot delete admin' });

  // Cleanup: delete accounts and files
  await db.collection('accounts').deleteMany({ userId: req.params.id });
  await db.collection('tg_files').deleteMany({ userId: req.params.id });
  await db.collection('tg_folders').deleteMany({ userId: req.params.id });
  await db.collection('sessions').deleteMany({ userId: req.params.id });
  await db.collection('users').deleteOne({ _id: req.params.id });
  
  res.json({ success: true });
});

app.get('/api/admin/users/:id', requireAuth, async (req: any, res: any) => {
  if (!req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  const db = req.db;
  const { id } = req.params;

  const user = await db.collection('users').findOne({ _id: id });
  if (!user) return res.status(404).json({ error: 'User not found' });

  const accounts = await db.collection('accounts').find({ userId: id }).toArray();
  const fileCount = await db.collection('tg_files').countDocuments({ userId: id });

  res.json({
    user: {
      id: user._id,
      username: user.username,
      isActive: user.isActive !== false,
      isAdmin: !!user.isAdmin,
      createdAt: user.createdAt,
      tgIds: user.tgIds || []
    },
    accounts,
    stats: {
      fileCount
    }
  });
});

app.get('/api/admin/settings', requireAuth, async (req: any, res: any) => {
  if (!req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  const db = req.db;
  const settings = await db.collection('settings').find({}).toArray();
  const config: any = {};
  settings.forEach((s: any) => config[s.key] = s.value);
  res.json(config);
});

app.post('/api/admin/settings', requireAuth, async (req: any, res: any) => {
  if (!req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  const db = req.db;
  const { key, value } = req.body;
  await db.collection('settings').updateOne({ key }, { $set: { value } }, { upsert: true });
  res.json({ success: true });
});

app.post('/api/logout', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    const database = await connectToMongo();
    await database.collection('sessions').deleteOne({ token });
  }
  res.json({ success: true });
});

// ─── TG Drive – register a channel as an account ─────────────────────────────
app.post('/api/tgdrive/register', requireAuth, async (req: any, res: any) => {
  const { channelId, driveName } = req.body;
  if (!channelId) return res.status(400).json({ error: 'channelId is required' });

  const userId   = req.userId;
  const database = req.db;
  const name     = (driveName || '').trim() || 'TG Drive';

  try {
    const admins = await bot!.telegram.getChatAdministrators(channelId);
    const botInfo = await bot!.telegram.getMe();
    const isBotAdmin = admins.some((a: any) => a.user.id === botInfo.id);
    if (!isBotAdmin) return res.status(400).json({ error: 'Bot is not an admin in this channel' });
  } catch (e: any) {
    return res.status(400).json({ error: `Cannot access channel: ${e.message}. Make sure the bot is an admin in the channel.` });
  }

  const existingAccount = await database.collection('accounts').findOne({ channelId, userId: { $ne: userId } });
  if (existingAccount) return res.status(400).json({ error: 'This channel is already linked to another Cloudyte account.' });

  await database.collection('accounts').updateOne(
    { userId, channelId, accountType: 'tgdrive' },
    { $set: { userId, channelId, accountType: 'tgdrive', name, linkedAt: new Date().toISOString() } },
    { upsert: true }
  );

  const acc = await database.collection('accounts').findOne({ userId, channelId, accountType: 'tgdrive' });
  const newAccountId = acc!._id;

  // Re-link orphaned files if any (from old account ids but same channel)
  const existingAccountIds = (await database.collection('accounts').find({}, { projection: { _id: 1 } }).toArray()).map((a: any) => a._id);
  await database.collection('tg_files').updateMany(
    { accountId: { $nin: existingAccountIds }, userId: userId },
    { $set: { accountId: newAccountId } }
  );
  await database.collection('tg_folders').updateMany(
    { accountId: { $nin: existingAccountIds }, userId: userId },
    { $set: { accountId: newAccountId } }
  );

  res.json({ success: true, id: newAccountId.toString(), channelId, name });
});

// ─── User settings ────────────────────────────────────────────────────────────
app.post('/api/user/settings', requireAuth, async (req: any, res: any) => {
  const { backupEnabled, backupAccId, isDefaultAccId } = req.body;
  const userId   = req.userId;
  const database = req.db;

  const update: any = {};
  if (backupEnabled !== undefined) update.backupEnabled = backupEnabled;
  if (backupAccId !== undefined) update.backupAccId = backupAccId;
  
  if (Object.keys(update).length > 0) {
    await database.collection('users').updateOne({ _id: userId }, { $set: update });
  }

  if (isDefaultAccId) {
    await database.collection('accounts').updateMany({ userId }, { $set: { isDefault: false } });
    await database.collection('accounts').updateOne({ _id: new ObjectId(isDefaultAccId), userId }, { $set: { isDefault: true } });
  }
  res.json({ success: true });
});

// ─── /api/me ──────────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, async (req: any, res: any) => {
  if (req.isAdmin && !req.user) {
    return res.json({ 
      authenticated: true, 
      username: 'System Admin', 
      isAdmin: true,
      settings: { 
        username: 'admin', 
        backupEnabled: false, 
        backupAccId: null 
      } 
    });
  }
  const user = req.user;
  res.json({ 
    authenticated: true, 
    username: user.username, 
    isAdmin: !!user.isAdmin,
    settings: { 
      username: user.username, 
      backupEnabled: user.backupEnabled || false, 
      backupAccId: user.backupAccId || null 
    } 
  });
});

// ─── /api/accounts ────────────────────────────────────────────────────────────
app.get('/api/accounts', requireAuth, async (req: any, res: any) => {
  const database = req.db;
  const { userId } = req.query;
  const query: any = {};
  
  if (req.isAdmin) {
    if (userId) query.userId = String(userId);
  } else {
    query.userId = req.userId;
  }

  const accounts = await database.collection('accounts').find(query).toArray();

  // Deduplicate: for tgdrive key is channelId, for others key is email
  const seen    = new Map();
  const unique  = accounts.filter((a: any) => {
    const key = a.accountType === 'tgdrive' ? `tgdrive:${a.channelId}` : (a.email || a._id.toString());
    if (seen.has(key)) return false;
    seen.set(key, true);
    return true;
  });

  const enriched = await Promise.all(unique.map(async (acc: any) => {
    if (acc.accountType === 'tgdrive') {
      // For TG Drive: compute storage from tg_files collection
      try {
        const pipeline = [
          { $match: { accountId: acc._id } },
          { $group: { _id: null, total: { $sum: '$size' }, count: { $sum: 1 } } },
        ];
        const [agg] = await database.collection('tg_files').aggregate(pipeline).toArray();
        const usedBytes = agg?.total || 0;
        return {
          id:          acc._id.toString(),
          name:        acc.name || 'TG Drive',
          email:       `Channel: ${acc.channelId}`,
          channelId:   acc.channelId,
          accountType: 'tgdrive',
          usage:       (usedBytes / (1024 ** 3)).toFixed(2) + ' GB',
          total:       '∞',
          percentage:  0,
          fileCount:   agg?.count || 0,
          isDefault:   acc.isDefault || false,
        };
      } catch {
        return { id: acc._id.toString(), name: acc.name || 'TG Drive', email: `Channel: ${acc.channelId}`, channelId: acc.channelId, accountType: 'tgdrive', usage: '0 GB', total: '∞', percentage: 0, error: false };
      }
    }

    try {
      const CACHE_TTL = 300000;
      const now       = Date.now();
      if (acc.quotaCachedAt && (now - new Date(acc.quotaCachedAt).getTime()) < CACHE_TTL) {
        return { id: acc._id.toString(), name: acc.name, email: acc.email, usage: (Number(acc.quotaUsage) / (1024 ** 3)).toFixed(1) + ' GB', total: (Number(acc.quotaLimit) / (1024 ** 3)).toFixed(0) + ' GB', percentage: Math.round((Number(acc.quotaUsage) / Number(acc.quotaLimit)) * 100), accountType: acc.accountType || 'google' };
      }
      let quotaUsage = '0', quotaLimit = '1', displayName = acc.name;
      if (acc.accountType === 'onedrive') {
        const c = await getOneDriveClient(acc.tokens, acc._id.toString());
        const d = await c.api('/me/drive').get();
        quotaUsage = d.quota.used; quotaLimit = d.quota.total; displayName = acc.name || 'OneDrive';
      } else {
        const drive  = await getDriveClient(acc.tokens);
        const about  = await drive.about.get({ fields: 'storageQuota,user' });
        quotaUsage   = about.data.storageQuota?.usage || '0';
        quotaLimit   = about.data.storageQuota?.limit || '1';
        displayName  = about.data.user?.displayName || acc.name;
      }
      await database.collection('accounts').updateOne({ _id: acc._id }, { $set: { quotaUsage, quotaLimit, quotaCachedAt: new Date(), name: displayName } });
      return { id: acc._id.toString(), name: displayName, email: acc.email, usage: (Number(quotaUsage) / (1024 ** 3)).toFixed(1) + ' GB', total: (Number(quotaLimit) / (1024 ** 3)).toFixed(0) + ' GB', percentage: Math.round((Number(quotaUsage) / Number(quotaLimit)) * 100), accountType: acc.accountType || 'google' };
    } catch {
      return { id: acc._id.toString(), name: acc.name || 'Disconnected', email: acc.email || acc.channelId, error: true, percentage: 0, accountType: acc.accountType || 'google' };
    }
  }));
  res.json(enriched);
});

app.delete('/api/accounts/:id', requireAuth, async (req: any, res: any) => {
  const { id }   = req.params;
  const database = req.db;
  const query: any = { _id: new ObjectId(id) };
  if (!req.isAdmin) { 
    if (!req.userId) return res.status(401).json({ error: 'Auth context missing' }); 
    query.userId = String(req.userId); 
  }
  await database.collection('accounts').deleteOne(query);
  res.json({ success: true });
});

// ─── /api/files ───────────────────────────────────────────────────────────────
app.get('/api/files', requireAuth, async (req: any, res: any) => {
  const { accountId, folderId, search } = req.query;
  const userId        = req.userId;
  const database      = req.db;
  if (!accountId || !database) return res.json([]);

  const query: any = { _id: new ObjectId(accountId as string) };
  if (!req.isAdmin && userId) query.userId = String(userId);
  const account = await database.collection('accounts').findOne(query);
  if (!account) return res.status(404).json({ error: 'Account not found' });

  try {
    // ── TG Drive ──────────────────────────────────────────────────────────────
    if (account.accountType === 'tgdrive') {
      const currentFolder = (!folderId || folderId === 'root') ? '' : (folderId as string);

      let tgFiles: any[];
      let folderDocs: any[] = [];

      if (search) {
        const regex = new RegExp((search as string).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
        tgFiles = await database.collection('tg_files')
          .find({ accountId: new ObjectId(accountId as string), name: regex })
          .sort({ date: -1 }).limit(100).toArray();
      } else {
        const [filesResult, foldersResult] = await Promise.all([
          database.collection('tg_files')
            .find({ accountId: new ObjectId(accountId as string), folder: currentFolder })
            .sort({ date: -1 }).limit(100).toArray(),
          database.collection('tg_folders')
            .find({ accountId: new ObjectId(accountId as string), path: { $regex: `^${currentFolder ? currentFolder + '/' : ''}[^/]+$` } })
            .toArray()
        ]);
        tgFiles = filesResult;
        folderDocs = foldersResult;
      }

      const folders = folderDocs.map((f: any) => ({
        id:        `folder:${f.path}`,
        name:      f.name,
        type:      'folder',
        size:      '-',
        modified:  '-',
        createdAt: '-',
        folder:    f.path,
        isTgDrive: true,
      }));

      return res.json([...folders, ...tgFiles.map(normaliseTgFile)]);
    }

    // ── External Drives (OneDrive / Google Drive) ──────────────────────────
    const cacheKey = `api:${account.accountType}:${accountId}:${folderId || 'root'}:${search || 'none'}`;
    const cached = search ? null : driveCache.get(cacheKey);
    if (cached) return res.json(cached);

    let rawFiles: any[] = [];
    if (account.accountType === 'onedrive') {
      const c = await getOneDriveClient(account.tokens, account._id.toString());
      if (search) {
        const r = await c.api(`/me/drive/root/search(q='${(search as string).replace(/'/g, "''")}')`).get();
        rawFiles = r.value.map((f: any) => ({ id: f.id, name: f.name, mimeType: f.folder ? 'folder' : (f.file?.mimeType || ''), size: f.size, modifiedTime: f.lastModifiedDateTime, createdTime: f.createdDateTime, webViewLink: f.webUrl }));
      } else {
        const effectiveFolderId = (folderId as string) || 'root';
        const itemPath = effectiveFolderId === 'root' ? '/me/drive/root' : `/me/drive/items/${effectiveFolderId}`;
        const r = await c.api(`${itemPath}/children`).get();
        rawFiles = r.value.map((f: any) => ({ id: f.id, name: f.name, mimeType: f.folder ? 'folder' : (f.file?.mimeType || ''), size: f.size, modifiedTime: f.lastModifiedDateTime, createdTime: f.createdDateTime, webViewLink: f.webUrl }));
      }
    } else {
      // ── Google Drive ────────────────────────────────────────────────────────
      const drive = await getDriveClient(account.tokens);
      const qParts = ['trashed = false'];
      if (search) qParts.push(`name contains '${(search as string).replace(/'/g, "\\'")}'`);
      else qParts.push(`'${folderId || 'root'}' in parents`);
      const list  = await drive.files.list({ pageSize: 100, q: qParts.join(' and '), fields: 'files(id,name,mimeType,size,modifiedTime,createdTime,webViewLink)', orderBy: 'folder,name' });
      rawFiles = list.data.files || [];
    }

    const files = rawFiles.map(f => {
      const mime = f.mimeType || '';
      let type   = 'other';
      if (mime.includes('folder') || mime === 'folder') type = 'folder';
      else if (mime.includes('pdf'))    type = 'pdf';
      else if (mime.includes('image'))  type = 'image';
      else if (mime.includes('video'))  type = 'video';
      else if (mime.includes('audio'))  type = 'audio';
      else if (mime.includes('spreadsheet') || mime.includes('excel')) type = 'sheet';
      else if (mime.includes('document') || mime.includes('word'))     type = 'doc';
      else if (mime.includes('presentation') || mime.includes('powerpoint')) type = 'slide';
      else if (mime.includes('zip') || mime.includes('rar') || mime.includes('7z')) type = 'zip';
      return { id: f.id, name: f.name, type, size: f.size ? (Number(f.size) / (1024 ** 2)).toFixed(1) + ' MB' : '-', modified: f.modifiedTime ? new Date(f.modifiedTime).toLocaleDateString() : '-', createdAt: f.createdTime ? new Date(f.createdTime).toLocaleDateString() : '-', webViewLink: f.webViewLink };
    });

    if (!search) driveCache.set(cacheKey, files, 60); // Cache for 60s
    res.json(files);
  } catch (err: any) {
    console.error('Files API error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Delete file ──────────────────────────────────────────────────────────────
app.delete('/api/files/:fileId', requireAuth, async (req: any, res: any) => {
  const { fileId }    = req.params;
  const { accountId } = req.query;
  const userId        = req.userId;
  const database      = req.db;

  const query: any = { _id: new ObjectId(accountId as string) };
  if (!req.isAdmin && userId) query.userId = String(userId);
  const account = await database.collection('accounts').findOne(query);
  if (!account) return res.status(404).json({ error: 'Account not found' });

  try {
    if (account.accountType === 'tgdrive') {
      const meta = await database.collection('tg_files').findOne({ _id: new ObjectId(fileId) });
      if (!meta) return res.status(404).json({ error: 'File not found' });
      const telegram = await getTgClient();
      const peer     = await resolvePeer(telegram, account.channelId);
      try { await telegram.deleteMessages(peer, [meta.messageId], { revoke: true }); } catch { /* message may already be gone */ }
      await database.collection('tg_files').deleteOne({ _id: new ObjectId(fileId) });
    } else if (account.accountType === 'onedrive') {
      const c = await getOneDriveClient(account.tokens, account._id.toString());
      await c.api(`/me/drive/items/${fileId}`).delete();
    } else {
      const drive = await getDriveClient(account.tokens);
      await drive.files.delete({ fileId });
    }
    invalidateDriveCache(accountId as string);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Rename file ──────────────────────────────────────────────────────────────
app.patch('/api/files/:fileId', requireAuth, async (req: any, res: any) => {
  const { fileId }    = req.params;
  const { accountId } = req.query;
  const { name }      = req.body;
  const userId        = req.userId;
  const database      = req.db;

  const query: any = { _id: new ObjectId(accountId as string) };
  if (!req.isAdmin && userId) query.userId = String(userId);
  const account = await database.collection('accounts').findOne(query);
  if (!account) return res.status(404).json({ error: 'Account not found' });

  try {
    if (account.accountType === 'tgdrive') {
      await database.collection('tg_files').updateOne({ _id: new ObjectId(fileId) }, { $set: { name } });
    } else if (account.accountType === 'onedrive') {
      const c = await getOneDriveClient(account.tokens, account._id.toString());
      await c.api(`/me/drive/items/${fileId}`).patch({ name });
    } else {
      const drive = await getDriveClient(account.tokens);
      await drive.files.update({ fileId, requestBody: { name } });
    }
    invalidateDriveCache(accountId as string);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Create folder ────────────────────────────────────────────────────────────
app.post('/api/folders', requireAuth, async (req: any, res: any) => {
  const { accountId } = req.query;
  const { name, parentId } = req.body;
  const userId        = req.userId;
  const database      = req.db;

  const query: any = { _id: new ObjectId(accountId as string) };
  if (!req.isAdmin && userId) query.userId = String(userId);
  const account = await database.collection('accounts').findOne(query);
  if (!account) return res.status(404).json({ error: 'Account not found' });

  try {
    if (account.accountType === 'tgdrive') {
      const parentPath = (!parentId || parentId === 'root') ? '' : parentId;
      const folderPath = parentPath ? `${parentPath}/${name}` : name;
      await database.collection('tg_folders').updateOne(
        { accountId: new ObjectId(accountId as string), path: folderPath },
        { $set: { accountId: new ObjectId(accountId as string), name, path: folderPath, createdAt: Math.floor(Date.now() / 1000) } },
        { upsert: true }
      );
    } else if (account.accountType === 'onedrive') {
      const c = await getOneDriveClient(account.tokens, account._id.toString());
      const parentPath = (!parentId || parentId === 'root') ? '/me/drive/root' : `/me/drive/items/${parentId}`;
      await c.api(`${parentPath}/children`).post({ name, folder: {}, '@microsoft.graph.conflictBehavior': 'rename' });
    } else {
      const drive = await getDriveClient(account.tokens);
      await drive.files.create({ requestBody: { name, parents: [parentId || 'root'], mimeType: 'application/vnd.google-apps.folder' } });
    }
    invalidateDriveCache(accountId as string);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Upload ───────────────────────────────────────────────────────────────────
app.post('/api/upload/:accountId', requireAuth, upload.single('file'), async (req: any, res: any) => {
  const { accountId } = req.params;
  const { folderId }  = req.body;
  const file          = req.file;
  const userId        = req.userId;
  const database      = req.db;

  if (!file) return res.status(400).json({ error: 'No file uploaded' });

  const query: any = { _id: new ObjectId(accountId) };
  if (!req.isAdmin && userId) query.userId = String(userId);
  const account = await database.collection('accounts').findOne(query);
  if (!account) return res.status(404).json({ error: 'Account not found' });

  try {
    if (account.accountType === 'tgdrive') {
      const folder = (!folderId || folderId === 'root') ? '' : folderId;
      await tgUploadFile(accountId, account.channelId, file.buffer, file.originalname, file.mimetype, folder);
    } else if (account.accountType === 'onedrive') {
      const c          = await getOneDriveClient(account.tokens, accountId);
      const parentPath = (!folderId || folderId === 'root') ? '/me/drive/root' : `/me/drive/items/${folderId}`;
      const fileName   = encodeURIComponent(file.originalname);
      if (file.size <= 4 * 1024 * 1024) {
        await c.api(`${parentPath}:/${fileName}:/content`).put(file.buffer);
      } else {
        const uploadSession = await c.api(`${parentPath}:/${fileName}:/createUploadSession`).post({ item: { '@microsoft.graph.conflictBehavior': 'replace', name: file.originalname } });
        const uploadUrl  = uploadSession.uploadUrl;
        const chunkSize  = 320 * 1024 * 10;
        for (let start = 0; start < file.size; start += chunkSize) {
          const end   = Math.min(start + chunkSize, file.size);
          const chunk = file.buffer.slice(start, end);
          await axios.put(uploadUrl, chunk, { headers: { 'Content-Range': `bytes ${start}-${end - 1}/${file.size}`, 'Content-Length': chunk.length } });
        }
      }
    } else {
      const drive       = await getDriveClient(account.tokens);
      const bufferStream = new stream.PassThrough();
      bufferStream.end(file.buffer);
      await drive.files.create({ requestBody: { name: file.originalname, parents: [folderId || 'root'] }, media: { mimeType: file.mimetype, body: bufferStream } });
    }
    invalidateDriveCache(accountId);
    res.json({ success: true });
  } catch (err: any) {
    console.error('Upload error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Download (authed) ────────────────────────────────────────────────────────
app.get('/api/download/:accountId/:fileId', requireAuth, async (req: any, res: any) => {
  const { accountId, fileId } = req.params;
  const userId                = req.userId;
  const database              = req.db;

  try {
    const query: any = { _id: new ObjectId(accountId) };
    if (!req.isAdmin && userId) query.userId = String(userId);
    const account = await database.collection('accounts').findOne(query);
    if (!account) return res.status(404).send('Account not found');

    if (account.accountType === 'tgdrive') {
      const meta = await database.collection('tg_files').findOne({ _id: new ObjectId(fileId) });
      if (!meta) return res.status(404).send('File not found');
      res.setHeader('Content-Disposition', `${req.query.preview === '1' ? 'inline' : 'attachment'}; filename="${encodeURIComponent(meta.name)}"`);
      await tgStreamFile(meta.messageId, account.channelId, req, res, meta);
      return;
    }

    if (account.accountType === 'onedrive') {
      const c    = await getOneDriveClient(account.tokens, account._id.toString());
      const item = await c.api(`/me/drive/items/${fileId}`).get();
      const dlUrl = item['@microsoft.graph.downloadUrl'];
      if (!dlUrl) return res.status(404).send('Download link not available');
      const response = await axios.get(dlUrl, { responseType: 'stream' });
      res.setHeader('Content-Disposition', `${req.query.preview === '1' ? 'inline' : 'attachment'}; filename="${encodeURIComponent(item.name)}"`);
      res.setHeader('Content-Type', item.file?.mimeType || 'application/octet-stream');
      return response.data.pipe(res);
    }

    const drive    = await getDriveClient(account.tokens);
    const file     = await drive.files.get({ fileId, fields: 'name,mimeType' });
    res.setHeader('Content-Disposition', `${req.query.preview === '1' ? 'inline' : 'attachment'}; filename="${encodeURIComponent(file.data.name!)}"`);
    res.setHeader('Content-Type', file.data.mimeType!);
    const response = await drive.files.get({ fileId, alt: 'media' }, { responseType: 'stream' });
    response.data.pipe(res);
  } catch (err: any) {
    console.error('Download error:', err);
    res.status(500).send(err.message);
  }
});

// ─── Share ────────────────────────────────────────────────────────────────────
app.post('/api/share', requireAuth, async (req: any, res: any) => {
  const { accountId, fileId } = req.body;
  const userId                = req.userId;
  const database              = req.db;

  const query: any = { _id: new ObjectId(accountId) };
  if (!req.isAdmin && userId) query.userId = String(userId);
  const account = await database.collection('accounts').findOne(query);
  if (!account) return res.status(404).json({ error: 'Account not found' });

  try {
    if (account.accountType === 'tgdrive') {
      const meta = await database.collection('tg_files').findOne({ _id: new ObjectId(fileId) });
      if (!meta) return res.status(404).json({ error: 'File not found' });
      let { shareId } = meta;
      if (!shareId) {
        shareId = nanoid(6);
        await database.collection('tg_files').updateOne({ _id: meta._id }, { $set: { shareId } });
      }
      return res.json({ success: true, shareUrl: `${process.env.APP_URL}/s/${shareId}` });
    }

    const shareId = nanoid(6);
    await database.collection('shares').insertOne({ shareId, accountId: new ObjectId(accountId), fileId, createdAt: new Date().toISOString() });
    res.json({ success: true, shareUrl: `${process.env.APP_URL}/s/${shareId}` });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Move ────────────────────────────────────────────────────────────────────
app.post('/api/files/move', requireAuth, async (req: any, res: any) => {
  const { sourceAccountId, fileId, targetAccountId, targetFolderId } = req.body;
  const userId = req.userId;
  const database = req.db;

  if (sourceAccountId !== targetAccountId) {
    return res.status(400).json({ error: 'Cross-account moving is not supported yet' });
  }

  const query: any = { _id: new ObjectId(sourceAccountId) };
  if (!req.isAdmin && userId) query.userId = String(userId);
  const account = await database.collection('accounts').findOne(query);
  if (!account) return res.status(404).json({ error: 'Account not found' });

  try {
    if (account.accountType === 'tgdrive') {
      await database.collection('tg_files').updateOne(
        { _id: new ObjectId(fileId), accountId: String(account._id) },
        { $set: { folderId: targetFolderId } }
      );
      return res.json({ success: true });
    } else if (account.accountType === 'google') {
      const drive = await getDriveClient(account.credentials);
      const file = await drive.files.get({ fileId, fields: 'parents' });
      const previousParents = file.data.parents?.join(',') || '';
      
      const realTargetId = targetFolderId === 'root' ? 'root' : targetFolderId;
      
      await drive.files.update({
        fileId,
        addParents: realTargetId,
        removeParents: previousParents,
        fields: 'id, parents'
      });
      return res.json({ success: true });
    } else if (account.accountType === 'onedrive') {
      const token = account.credentials.access_token;
      const realTargetId = targetFolderId === 'root' ? 'root' : targetFolderId;
      const url = `https://graph.microsoft.com/v1.0/me/drive/items/${fileId}`;
      await axios.patch(url, {
        parentReference: {
          id: realTargetId === 'root' ? (await axios.get('https://graph.microsoft.com/v1.0/me/drive/root', { headers: { Authorization: `Bearer ${token}` } })).data.id : realTargetId
        }
      }, {
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
      });
      return res.json({ success: true });
    }
    res.status(400).json({ error: 'Unsupported account type' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Public download (no auth) ────────────────────────────────────────────────
app.get('/api/public/download/:shareId', async (req, res) => {
  const { shareId } = req.params;
  const database    = await connectToMongo();

  try {
    // Check TG Drive files first
    const tgMeta = await database.collection('tg_files').findOne({ shareId });
    if (tgMeta) {
      const account = await database.collection('accounts').findOne({ _id: tgMeta.accountId });
      if (!account) return res.status(404).send('Account disconnected');
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(tgMeta.name)}"`);
      res.setHeader('Content-Type', tgMeta.mimeType || 'application/octet-stream');
      await tgStreamFile(tgMeta.messageId, account.channelId, req, res, tgMeta);
      return;
    }

    // Fallback to cloud shares
    const share   = await database.collection('shares').findOne({ shareId });
    if (!share) return res.status(404).send('Share link expired');
    const account = await database.collection('accounts').findOne({ _id: share.accountId });
    if (!account) return res.status(404).send('Account disconnected');

    if (account.accountType === 'onedrive') {
      const c    = await getOneDriveClient(account.tokens, account._id.toString());
      const item = await c.api(`/me/drive/items/${share.fileId}`).get();
      const dlUrl = item['@microsoft.graph.downloadUrl'];
      const r    = await axios.get(dlUrl, { responseType: 'stream' });
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(item.name)}"`);
      res.setHeader('Content-Type', item.file?.mimeType || 'application/octet-stream');
      return r.data.pipe(res);
    }

    const drive    = await getDriveClient(account.tokens);
    const file     = await drive.files.get({ fileId: share.fileId, fields: 'name,mimeType' });
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.data.name!)}"`);
    res.setHeader('Content-Type', file.data.mimeType!);
    const response = await drive.files.get({ fileId: share.fileId, alt: 'media' }, { responseType: 'stream' });
    response.data.pipe(res);
  } catch (err: any) {
    if (!res.headersSent) res.status(500).send('Download failed');
  }
});

// ─── Public share page ────────────────────────────────────────────────────────
app.get('/s/:shareId', async (req, res) => {
  const { shareId } = req.params;
  const database    = await connectToMongo();

  try {
    // Check TG Drive
    const tgMeta = await database.collection('tg_files').findOne({ shareId });
    if (tgMeta) {
      const sizeMB = tgMeta.size ? (Number(tgMeta.size) / (1024 ** 2)).toFixed(2) + ' MB' : 'Unknown size';
      return res.send(buildSharePage(tgMeta.name, sizeMB, tgMeta.mimeType || '', null, shareId, true));
    }

    // Cloud shares
    const share = await database.collection('shares').findOne({ shareId });
    if (!share) return res.status(404).send('Share link expired or invalid');
    const account = await database.collection('accounts').findOne({ _id: share.accountId });
    if (!account) return res.status(404).send('Account disconnected');

    if (account.accountType === 'onedrive') {
      const c    = await getOneDriveClient(account.tokens, account._id.toString());
      const item = await c.api(`/me/drive/items/${share.fileId}`).get();
      const sizeMB = item.size ? (Number(item.size) / (1024 ** 2)).toFixed(2) + ' MB' : 'Unknown size';
      return res.send(buildSharePage(item.name, sizeMB, item.file?.mimeType || '', null, shareId, false));
    }

    const drive  = await getDriveClient(account.tokens);
    const file   = await drive.files.get({ fileId: share.fileId, fields: 'name,mimeType,size,thumbnailLink' });
    const sizeMB = file.data.size ? (Number(file.data.size) / (1024 ** 2)).toFixed(2) + ' MB' : 'Unknown size';
    const thumb  = file.data.mimeType?.startsWith('image/') ? file.data.thumbnailLink?.replace('=s220', '=s1000') || null : null;
    return res.send(buildSharePage(file.data.name!, sizeMB, file.data.mimeType!, thumb, shareId, false));
  } catch {
    res.status(500).send('Error loading shared file');
  }
});

const escapeHTML = (str: string) => {
  return str.replace(/[&<>"']/g, (m) =>({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[m as keyof { '&': string; '<': string; '>': string; '"': string; "'": string }] || m);
};

function buildSharePage(name: string, size: string, mimeType: string, thumb: string | null, shareId: string, isTg: boolean) {
  const icon = isTg
    ? `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="white"><path d="m20.303 2.38-18 7a.5.5 0 0 0 .076.953l4.382.972 1.818 5.454a.5.5 0 0 0 .844.157l2.425-2.888 4.854 3.56a.5.5 0 0 0 .784-.288L21 2.9a.5.5 0 0 0-.697-.52zm-1.19 1.71-9.452 9.2-2.113-6.337L19.113 4.09z"/></svg>`
    : `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M17.5 19.5h-11a3 3 0 0 1-3-3V6.5a3 3 0 0 1 3-3h11a3 3 0 0 1 3 3v10a3 3 0 0 1-3 3Z"/><path d="M7.5 11h9"/><path d="M7.5 15h9"/><path d="M7.5 7h9"/></svg>`;
  return `
    <html>
      <head><title>${name} - Cloudyte Share</title><meta name="viewport" content="width=device-width, initial-scale=1"><script src="https://cdn.tailwindcss.com"></script></head>
      <body class="bg-slate-950 text-white flex items-center justify-center min-h-screen p-6 font-sans">
        <div class="max-w-lg w-full bg-slate-900 border border-slate-800 p-8 rounded-3xl shadow-2xl text-center space-y-6">
          <div class="w-20 h-20 bg-indigo-600 rounded-2xl flex items-center justify-center mx-auto shadow-lg shadow-indigo-500/20">${icon}</div>
          <div>
            <h1 class="text-2xl font-black truncate" title="${escapeHTML(name)}">${escapeHTML(name)}</h1>
            <p class="text-slate-500 font-bold uppercase tracking-widest text-[10px] mt-2">${escapeHTML(size)} • ${escapeHTML(mimeType || 'file')}</p>
            ${isTg ? '<p class="text-indigo-400 text-[10px] font-bold uppercase tracking-widest mt-1">📡 Telegram Storage</p>' : ''}
          </div>
          ${thumb ? `<img src="${thumb}" class="rounded-xl w-full aspect-video object-cover border border-slate-800" referrerPolicy="no-referrer" />` : ''}
          <a href="/api/public/download/${shareId}" class="block w-full bg-white text-black py-4 rounded-2xl font-black text-lg hover:bg-slate-100 transition-all active:scale-[0.98]">Download File</a>
          <p class="text-[10px] text-slate-600 font-bold uppercase tracking-widest">Shared via Cloudyte</p>
        </div>
      </body>
    </html>`;
}

// ─── OAuth routes (Google + Microsoft) ───────────────────────────────────────
const baseUrl     = (process.env.APP_URL || '').replace(/\/$/, '');
const redirectUri = `${baseUrl}/auth/google/callback`;
const oauth2Client = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, redirectUri);

app.get('/api/auth/drive-link', requireAuth, async (req: any, res: any) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Auth token missing' });
  const url = oauth2Client.generateAuthUrl({ access_type: 'offline', scope: ['https://www.googleapis.com/auth/drive', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'], state: token, prompt: 'consent' });
  res.json({ url });
});

app.get('/auth/link', (req, res) => {
  const tgId = req.query.tgId as string;
  const url  = oauth2Client.generateAuthUrl({ access_type: 'offline', scope: ['https://www.googleapis.com/auth/drive', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'], state: JSON.stringify({ tgId }), prompt: 'consent' });
  res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, state } = req.query;
  const database        = await connectToMongo();
  try {
    const { tokens } = await oauth2Client.getToken(code as string);
  let userId: string | null = null;
  const stateStr = state as string;
  if (stateStr === AUTH_TOKEN) { userId = 'admin'; }
  else if (stateStr.startsWith('{')) { try { const p = JSON.parse(stateStr); userId = p.userId ? String(p.userId) : null; } catch { /* ignore */ } }
  else { const session = await database.collection('sessions').findOne({ token: stateStr }); if (session) userId = String(session.userId); }
  if (!userId) return res.status(401).send('Session lost. Please try again.');
  const authClient = new google.auth.OAuth2(); authClient.setCredentials(tokens);
  const about = await google.drive({ version: 'v3', auth: authClient }).about.get({ fields: 'user' });
  const ui    = about.data.user;
  if (userId && database && ui) {
    await database.collection('accounts').updateOne(
      { userId: String(userId), email: ui.emailAddress },
      { $set: { tokens, linkedAt: new Date().toISOString(), name: ui.displayName, accountType: 'google' } },
      { upsert: true }
    );
  }
    res.send(oauthSuccessPage('Google Drive'));
  } catch { res.status(500).send('Authentication failed'); }
});

app.get('/api/auth/onedrive-link', requireAuth, async (req: any, res: any) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Auth token missing' });
  const url = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=${MICROSOFT_CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(MICROSOFT_REDIRECT_URI)}&response_mode=query&scope=${encodeURIComponent('files.readwrite.all User.Read offline_access')}&state=${encodeURIComponent(token)}&prompt=select_account`;
  res.json({ url });
});

app.get('/auth/microsoft/callback', async (req, res) => {
  const { code, state } = req.query;
  const database        = await connectToMongo();
  try {
    const r        = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', new URLSearchParams({ client_id: MICROSOFT_CLIENT_ID!, client_secret: MICROSOFT_CLIENT_SECRET!, code: code as string, redirect_uri: MICROSOFT_REDIRECT_URI, grant_type: 'authorization_code' }));
    const rawTokens = r.data;
    const tokens    = { ...rawTokens, expiry_date: Date.now() + Number(rawTokens.expires_in || 3600) * 1000 };
  let userId: string | null = null;
  const stateStr  = state as string;
  if (stateStr === AUTH_TOKEN) { userId = 'admin'; }
  else if (stateStr.startsWith('{')) { try { const p = JSON.parse(stateStr); userId = p.userId ? String(p.userId) : null; } catch { /* ignore */ } }
  else { const session = await database.collection('sessions').findOne({ token: stateStr }); if (session) userId = String(session.userId); }
  if (!userId) return res.status(401).send('Session lost. Please try again.');
  const msc  = Client.init({ authProvider: (done) => done(null, tokens.access_token) });
  const user = await msc.api('/me').get();
  if (userId && database && user) {
    await database.collection('accounts').updateOne(
      { userId: String(userId), email: user.userPrincipalName || user.mail },
      { $set: { tokens, linkedAt: new Date().toISOString(), name: user.displayName, accountType: 'onedrive' } },
      { upsert: true }
    );
  }
    res.send(oauthSuccessPage('OneDrive'));
  } catch { res.status(500).send('Authentication failed'); }
});

function oauthSuccessPage(service: string) {
  return `<html><body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;background:#f8fafc;margin:0"><div style="background:white;padding:2.5rem;border-radius:1.5rem;box-shadow:0 20px 25px -5px rgba(0,0,0,.1);text-align:center;max-width:400px;width:90%"><span style="font-size:32px">✅</span><h2 style="color:#1e1b4b;margin:.75rem 0;font-size:1.5rem">Success!</h2><p style="color:#64748b;margin-bottom:2rem">${service} linked to Cloudyte.</p><button onclick="window.close()" style="background:#4f46e5;color:white;border:none;padding:.75rem 2rem;border-radius:9999px;font-weight:600;cursor:pointer">Done</button></div><script>setTimeout(()=>window.close(),4000)</script></body></html>`;
}

// ─── Telegram Bot ─────────────────────────────────────────────────────────────
// All bot logic lives in telegram.ts. We pass the shared helpers it needs as
// dependencies. If TELEGRAM_BOT_TOKEN is missing, initBot() returns null and the
// web app keeps running normally without a bot.
const bot = initBot({
  connectToMongo,
  getUserIdByTg,
  getDriveClient,
  getOneDriveClient,
  getTgClient,
  resolvePeer,
  driveCache,
  invalidateDriveCache,
  nanoid,
  nanoid12,
  oauth2Client,
  MICROSOFT_CLIENT_ID,
  MICROSOFT_REDIRECT_URI,
});

// ─── Vite / static ────────────────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'production') {
  const vite = await createViteServer({ server: { middlewareMode: true }, appType: 'spa' });
  app.use(vite.middlewares);
} else {
  const distPath = path.join(process.cwd(), 'dist');
  app.use(express.static(distPath));
  app.get('*', (req, res) => res.sendFile(path.join(distPath, 'index.html')));
}

app.listen(Number(PORT), '0.0.0.0', () => console.log(`Cloudyte running at http://localhost:${PORT}`));
export default app;
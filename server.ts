import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const DB_PATH = path.join(__dirname, 'data', 'accounts.json');
const CONFIG_PATH = path.join(__dirname, 'data', 'config.json');

// Interface for user accounts
export interface AccountRecord {
  u: string;
  salt: string;
  h: string;
  data: string;
  createdAt: string;
  updatedAt: string;
}

// Ensure data folder exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Database Manager
class AccountDatabase {
  private filePath: string;
  private accounts: Record<string, AccountRecord> = {};

  constructor(filePath: string) {
    this.filePath = filePath;
    this.load();
  }

  private load(): void {
    if (fs.existsSync(this.filePath)) {
      try {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        this.accounts = JSON.parse(raw);
        console.log(`[Database] Loaded ${Object.keys(this.accounts).length} account(s) from ${this.filePath}`);
      } catch (err) {
        console.error('[Database] Error reading database file, initializing empty:', err);
        this.accounts = {};
        this.save();
      }
    } else {
      this.accounts = {};
      this.save();
    }
  }

  public save(): void {
    try {
      const tempPath = `${this.filePath}.tmp`;
      fs.writeFileSync(tempPath, JSON.stringify(this.accounts, null, 2), 'utf-8');
      fs.renameSync(tempPath, this.filePath);
    } catch (err) {
      console.error('[Database] Failed to save database file:', err);
      fs.writeFileSync(this.filePath, JSON.stringify(this.accounts, null, 2), 'utf-8');
    }
  }

  public get(u: string): AccountRecord | undefined {
    return this.accounts[u.toLowerCase()];
  }

  public set(u: string, record: Omit<AccountRecord, 'u' | 'createdAt' | 'updatedAt'>): AccountRecord {
    const key = u.toLowerCase();
    const existing = this.accounts[key];
    const now = new Date().toISOString();
    const fullRecord: AccountRecord = {
      u: key,
      salt: record.salt,
      h: record.h,
      data: record.data,
      createdAt: existing ? existing.createdAt : now,
      updatedAt: now,
    };
    this.accounts[key] = fullRecord;
    this.save();
    return fullRecord;
  }

  public updateData(u: string, data: string): AccountRecord | null {
    const key = u.toLowerCase();
    const existing = this.accounts[key];
    if (!existing) return null;
    existing.data = data;
    existing.updatedAt = new Date().toISOString();
    this.save();
    return existing;
  }

  public updateAccount(u: string, updates: { data?: string; salt?: string; h?: string }): AccountRecord | null {
    const key = u.toLowerCase();
    const existing = this.accounts[key];
    if (!existing) return null;
    if (updates.data !== undefined) existing.data = updates.data;
    if (updates.salt !== undefined) existing.salt = updates.salt;
    if (updates.h !== undefined) existing.h = updates.h;
    existing.updatedAt = new Date().toISOString();
    this.save();
    return existing;
  }

  public delete(u: string): boolean {
    const key = u.toLowerCase();
    if (this.accounts[key]) {
      delete this.accounts[key];
      this.save();
      return true;
    }
    return false;
  }

  public getAll(): AccountRecord[] {
    return Object.values(this.accounts);
  }
}

const db = new AccountDatabase(DB_PATH);

// Admin password helper (can be stored in env or changed dynamically)
function getAdminPassword(): string {
  if (fs.existsSync(CONFIG_PATH)) {
    try {
      const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
      if (cfg.adminPassword) return cfg.adminPassword;
    } catch {
      // ignore
    }
  }
  return process.env.ADMIN_PASSWORD || 'admin1234';
}

function setAdminPassword(newPass: string): void {
  let cfg: Record<string, any> = {};
  if (fs.existsSync(CONFIG_PATH)) {
    try {
      cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
    } catch {
      cfg = {};
    }
  }
  cfg.adminPassword = newPass;
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), 'utf-8');
}

// Active admin sessions
const activeAdminTokens = new Set<string>();

function verifyAdminAuth(req: Request): boolean {
  const authHeader = req.headers['authorization'];
  const token = (req.headers['x-admin-token'] as string) || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : '');
  const passHeader = req.headers['x-admin-password'] as string;
  const currentAdminPass = getAdminPassword();

  if (token && activeAdminTokens.has(token)) {
    return true;
  }
  if (passHeader && passHeader === currentAdminPass) {
    return true;
  }
  return false;
}

function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if (verifyAdminAuth(req)) {
    return next();
  }
  res.status(401).json({ error: 'Unauthorized: Valid admin password or token required.' });
}

// Start Express Server
async function startServer() {
  const app = express();

  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // --- API Routes ---
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      accountsCount: db.getAll().length,
      time: new Date().toISOString(),
    });
  });

  // Check / Fetch specific account
  app.get('/api/accounts/:u', (req, res) => {
    const u = req.params.u;
    const account = db.get(u);
    if (!account) {
      return res.status(404).json({ exists: false, message: 'Account not found' });
    }
    res.json({
      exists: true,
      account: {
        u: account.u,
        salt: account.salt,
        h: account.h,
        data: account.data,
        updatedAt: account.updatedAt,
      },
    });
  });

  // Create new account
  app.post('/api/accounts', (req, res) => {
    const { u, salt, h, data } = req.body;
    if (!u || typeof u !== 'string') {
      return res.status(400).json({ error: 'Username is required' });
    }
    const cleanU = u.trim().toLowerCase();
    if (!/^[a-z0-9_]{3,20}$/.test(cleanU)) {
      return res.status(400).json({ error: 'Username must be 3–20 letters, numbers or _' });
    }
    if (!salt || !h) {
      return res.status(400).json({ error: 'Password hash and salt are required' });
    }
    if (db.get(cleanU)) {
      return res.status(409).json({ error: 'That username is taken' });
    }

    const created = db.set(cleanU, {
      salt,
      h,
      data: typeof data === 'string' ? data : JSON.stringify(data || {}),
    });

    console.log(`[Account] Created user: ${cleanU}`);
    res.status(201).json({
      success: true,
      account: {
        u: created.u,
        updatedAt: created.updatedAt,
      },
    });
  });

  // Update account data
  app.put('/api/accounts/:u/data', (req, res) => {
    const u = req.params.u;
    const { data } = req.body;
    if (!data) {
      return res.status(400).json({ error: 'Missing data payload' });
    }
    const strData = typeof data === 'string' ? data : JSON.stringify(data);
    const updated = db.updateData(u, strData);
    if (!updated) {
      return res.status(404).json({ error: 'Account not found' });
    }
    res.json({ success: true, updatedAt: updated.updatedAt });
  });

  // Admin login
  app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    const adminPass = getAdminPassword();
    if (password && password === adminPass) {
      const token = 'apex_adm_' + crypto.randomBytes(24).toString('hex');
      activeAdminTokens.add(token);
      return res.json({ success: true, token });
    }
    res.status(401).json({ error: 'Invalid admin password' });
  });

  // Check admin token validity
  app.get('/api/admin/check', (req, res) => {
    if (verifyAdminAuth(req)) {
      return res.json({ valid: true });
    }
    res.status(401).json({ valid: false });
  });

  // Admin get all accounts
  app.get('/api/admin/accounts', requireAdmin, (req, res) => {
    const list = db.getAll().map((acc) => ({
      id: acc.u,
      u: acc.u,
      data: acc.data,
      createdAt: acc.createdAt,
      updatedAt: acc.updatedAt,
    }));
    res.json({ accounts: list });
  });

  // Admin update account
  app.put('/api/admin/accounts/:u', requireAdmin, (req, res) => {
    const u = req.params.u;
    const { data, salt, h } = req.body;
    const updated = db.updateAccount(u, {
      data: typeof data === 'string' ? data : data ? JSON.stringify(data) : undefined,
      salt,
      h,
    });
    if (!updated) {
      return res.status(404).json({ error: 'Account not found' });
    }
    console.log(`[Admin] Updated account ${u}`);
    res.json({ success: true, account: updated });
  });

  // Admin delete account
  app.delete('/api/admin/accounts/:u', requireAdmin, (req, res) => {
    const u = req.params.u;
    const success = db.delete(u);
    if (!success) {
      return res.status(404).json({ error: 'Account not found' });
    }
    console.log(`[Admin] Deleted account ${u}`);
    res.json({ success: true });
  });

  // Admin change password
  app.post('/api/admin/change-password', requireAdmin, (req, res) => {
    const { newPassword } = req.body;
    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 4) {
      return res.status(400).json({ error: 'New password must be at least 4 characters.' });
    }
    setAdminPassword(newPassword);
    console.log('[Admin] Admin password changed successfully');
    res.json({ success: true, message: 'Admin password updated successfully.' });
  });

  // --- Static & Frontend Serving ---
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Apex Server] Running on http://localhost:${PORT}`);
    console.log(`[Apex Server] Database file: ${DB_PATH}`);
  });
}

startServer().catch((err) => {
  console.error('[Apex Server] Fatal error starting server:', err);
  process.exit(1);
});

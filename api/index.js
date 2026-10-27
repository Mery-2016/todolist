import { neon } from '@neondatabase/serverless';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'smart-todo-super-secret-key-2026';

async function ensureTables(sql) {
  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name VARCHAR(100),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `;
  await sql`
    CREATE TABLE IF NOT EXISTS tasks (
      id VARCHAR(64) PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      data JSONB NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `;
}

function getUserFromToken(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  try {
    return jwt.verify(auth.split(' ')[1], JWT_SECRET);
  } catch {
    return null;
  }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (!process.env.DATABASE_URL) {
    return res.status(500).json({ error: 'DATABASE_URL не задан в настройках Vercel' });
  }

  const sql = neon(process.env.DATABASE_URL);

  try {
    await ensureTables(sql);
    const { action } = req.query;

    if (action === 'register' && req.method === 'POST') {
      const { email, password, name } = req.body;
      const existing = await sql`SELECT id FROM users WHERE email = ${email.toLowerCase()}`;
      if (existing.length > 0) return res.status(400).json({ error: 'Email уже занят' });

      const hash = await bcrypt.hash(password, 10);
      const [user] = await sql`
        INSERT INTO users (email, password_hash, name)
        VALUES (${email.toLowerCase()}, ${hash}, ${name || email.split('@')[0]})
        RETURNING id, email, name
      `;
      const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
      return res.status(201).json({ token, user });
    }

    if (action === 'login' && req.method === 'POST') {
      const { email, password } = req.body;
      const [user] = await sql`SELECT * FROM users WHERE email = ${email?.toLowerCase()}`;
      if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return res.status(401).json({ error: 'Неверный email или пароль' });
      }
      const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
      return res.status(200).json({ token, user: { id: user.id, email: user.email, name: user.name } });
    }

    const currentUser = getUserFromToken(req);
    if (!currentUser) return res.status(401).json({ error: 'Не авторизован' });

    if (action === 'tasks' && req.method === 'GET') {
      const rows = await sql`SELECT data FROM tasks WHERE user_id = ${currentUser.id} ORDER BY updated_at DESC`;
      return res.status(200).json({ tasks: rows.map(r => r.data) });
    }

    if (action === 'tasks' && req.method === 'POST') {
      const { tasks } = req.body;
      await sql`DELETE FROM tasks WHERE user_id = ${currentUser.id}`;
      for (const t of tasks || []) {
        await sql`INSERT INTO tasks (id, user_id, data) VALUES (${String(t.id)}, ${currentUser.id}, ${JSON.stringify(t)}::jsonb)`;
      }
      return res.status(200).json({ success: true });
    }

    return res.status(400).json({ error: 'Unknown action' });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}

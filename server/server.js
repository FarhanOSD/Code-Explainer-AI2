import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import ratelimit from 'express-rate-limit';
import helmet from 'helmet';
import OpenAI from 'openai';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();


// Express App Setup

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.use(helmet());

app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true,
  })
);

// Rate Limiter
const limiter = ratelimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again after 15 minutes',
});
app.use(limiter);


// SQLite DB Setup

const db = new sqlite3.Database('./users.db', err => {
  if (err) console.error('Error connecting to SQLite:', err.message);
  else console.log('✅ Connected to SQLite database');
});

// Users table
db.run(
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`
);

// Explanations table
db.run(
  `CREATE TABLE IF NOT EXISTS explanations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    code TEXT NOT NULL,
    language TEXT,
    explanation TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`
);


// OpenAI Client Setup

const client = new OpenAI({
  baseURL: 'https://openrouter.ai/api/v1',
  apiKey: process.env.API_KEY,
});


// Middleware: Verify JWT

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}


// Routes: Auth


// Register user
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res
      .status(400)
      .json({ error: 'Username and password are required' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO users (username, password) VALUES (?, ?)`,
      [username, hashedPassword],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint'))
            return res.status(400).json({ error: 'Username already exists' });
          return res.status(500).json({ error: 'Database error' });
        }
        res.status(201).json({ message: 'User registered successfully' });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Login user
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });

      const valid = await bcrypt.compare(password, user.password);
      if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

      const token = jwt.sign(
        { id: user.id, username: user.username },
        process.env.JWT_SECRET,
        {
          expiresIn: '1h',
        }
      );

      res.json({ message: 'Login successful', token });
    }
  );
});


// AI Explain Code Route

app.post('/api/explain-code', authenticateToken, async (req, res) => {
  try {
    const { code, language } = req.body;
    if (!code) return res.status(400).json({ error: 'Code is required' });

    const message = [
      {
        role: 'user',
        content: `Please explain the following ${
          language || ' '
        } code in simple Bangla line by line:\n\n${code}`,
      },
    ];

    const response = await client.chat.completions.create({
      model: 'ibm-granite/granite-4.0-h-micro',
      messages: message,
    });

    const explanation = response?.choices?.[0]?.message?.content;

    if (!explanation)
      return res
        .status(500)
        .json({ error: 'Failed to get explanation from AI model' });

    // Save explanation in DB
    db.run(
      `INSERT INTO explanations (user_id, code, language, explanation) VALUES (?, ?, ?, ?)`,
      [req.user.id, code, language, explanation],
      function (err) {
        if (err) console.error('DB save error:', err.message);
      }
    );

    res.json({ explanation, language });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// Get User's Explanations

app.get('/api/my-explanations', authenticateToken, (req, res) => {
  db.all(
    `SELECT * FROM explanations WHERE user_id = ? ORDER BY created_at DESC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ explanations: rows });
    }
  );
});

// Delete Explanation
app.delete('/api/explanations/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run(
    `DELETE FROM explanations WHERE id = ? AND user_id = ?`,
    [id, req.user.id],
    function (err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (this.changes === 0) return res.status(404).json({ error: 'Explanation not found or not owned by you' });
      res.json({ message: 'Explanation deleted successfully' });
    }
  );
});


// Start Server

const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});

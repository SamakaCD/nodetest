import express, { Request, Response } from 'express';
import { Pool } from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET!;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

app.use(express.json());

app.post('/register', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).send('Email and password are required');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const client = await pool.connect();
    const result = await client.query('INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id', [email, hashedPassword]);
    const userId = result.rows[0].id;
    client.release();

    const token = jwt.sign({ userId }, JWT_SECRET);
    res.status(201).json({ token });
  } catch (error) {
    console.error('Error registering user', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).send('Email and password are required');
    }

    const client = await pool.connect();
    const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    client.release();

    if (!user) {
      return res.status(401).send('Invalid email or password');
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).send('Invalid email or password');
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET);
    res.json({ token });
  } catch (error) {
    console.error('Error logging in', error);
    res.status(500).send('Internal Server Error');
  }
});

function authenticateToken(req: Request, res: Response, next: Function) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).send('Access token is required');
  }

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) {
      return res.status(403).send('Invalid token');
    }
    // @ts-ignore
    req.user = user;
    next();
  });
}

app.get('/user/me', authenticateToken, async (req: Request, res: Response) => {
  try {
    // @ts-ignore
    const userId = req.user.userId;

    const client = await pool.connect();
    const result = await client.query('SELECT id, email FROM users WHERE id = $1', [userId]);
    const user = result.rows[0];
    client.release();

    if (!user) {
      return res.status(404).send('User not found');
    }

    res.json(user);
  } catch (error) {
    console.error('Error fetching user', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/post/create', authenticateToken, async (req: Request, res: Response) => {
  try {
    const { text } = req.body;
    if (!text) {
      return res.status(400).send('Text is required');
    }

    // @ts-ignore
    const userId = req.user.userId;

    const client = await pool.connect();
    const result = await client.query('INSERT INTO posts (text, user_id) VALUES ($1, $2) RETURNING *', [text, userId]);
    const createdPost = result.rows[0];
    client.release();

    res.status(201).json(createdPost);
  } catch (error) {
    console.error('Error creating post', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/posts', authenticateToken, async (req: Request, res: Response) => {
  try {
    // @ts-ignore
    const userId = req.user.userId;

    const client = await pool.connect();
    const result = await client.query('SELECT * FROM posts WHERE user_id = $1', [userId]);
    const posts = result.rows;
    client.release();

    res.json(posts);
  } catch (error) {
    console.error('Error fetching posts', error);
    res.status(500).send('Internal Server Error');
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

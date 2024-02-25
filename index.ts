import express, { Request, Response } from 'express';
import { Pool } from 'pg';

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

app.use(express.json());

app.get('/hello', (req: Request, res: Response) => {
  res.send('hello world');
});

app.post('/post/create', async (req: Request, res: Response) => {
  try {
    const { text } = req.body;
    if (!text) {
      return res.status(400).send('Text is required');
    }

    const client = await pool.connect();
    const result = await client.query('INSERT INTO posts (text) VALUES ($1) RETURNING *', [text]);
    const createdPost = result.rows[0];
    client.release();

    res.status(201).json(createdPost);
  } catch (error) {
    console.error('Error executing query', error);
    res.status(500).send('Internal Server Error');
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

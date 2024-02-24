import express, { Request, Response } from 'express';

const app = express();
const PORT = process.env.PORT || 3000;

app.get('/hello', (req: Request, res: Response) => {
  res.send('hello world');
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
import express from "express";
import bcrypt from "bcrypt";
import rateLimit from "express-rate-limit";
import { pool, requireAuth } from "./db";

const app = express();
app.use(rateLimit({ windowMs: 60_000, limit: 10 }));

app.post("/login", async (req, res) => {
  const { rows } = await pool.query("SELECT id, password_hash FROM users WHERE email = $1", [req.body.email]);
  const ok = rows[0] && (await bcrypt.compare(req.body.password, rows[0].password_hash));
  res.status(ok ? 200 : 401).json({ ok });
});

app.get("/notes/:id", requireAuth, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM notes WHERE id = $1 AND owner_id = $2", [req.params.id, req.user.id]);
  res.json(rows[0] ?? null);
});

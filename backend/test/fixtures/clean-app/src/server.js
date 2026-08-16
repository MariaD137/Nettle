const express = require("express");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { z } = require("zod");

const app = express();
app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

function requireAuth(req, res, next) {
  try {
    jwt.verify(req.headers.authorization || "", process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Unauthorized" });
  }
}

app.get("/api/pets/:userId", requireAuth, (req, res) => {
  res.json({ userId: req.params.userId, pets: ["Milo", "Luna"] });
});

app.post("/api/login", (req, res) => {
  const token = jwt.sign({ user: req.body.email }, process.env.JWT_SECRET, { expiresIn: "15m" });
  const refreshToken = jwt.sign({ user: req.body.email, type: "refresh" }, process.env.JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, refreshToken });
});

app.post("/api/logout", requireAuth, (req, res) => {
  req.session && req.session.destroy();
  res.json({ ok: true });
});

app.listen(process.env.PORT || 3000);

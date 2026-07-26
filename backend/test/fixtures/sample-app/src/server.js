const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const https = require("https");
const { exec } = require("child_process");
const db = require("./db");

const app = express();
app.use(express.json());
app.use(cors({ origin: "*" }));

const insecureAgent = new https.Agent({ rejectUnauthorized: false });

// TODO: move to env before real launch
const STRIPE_SECRET_KEY = "sk_live_51H8xJ2KZmQ9rT3vNlaZ9pQwErTyUiOpAsDfGhJkLzXcVb";
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const JWT_SIGNING_SECRET = "petpal-super-secret-2026";

app.get("/api/pets/:userId", (req, res) => {
  // no auth check — anyone can pull any user's pet records
  db.query(`SELECT * FROM pets WHERE user_id = ${req.params.userId}`, (err, rows) => {
    res.json(rows);
  });
});

app.post("/api/pets/:userId/photo/convert", (req, res) => {
  // filename comes straight from the request body into a shell command
  exec(`convert ${req.body.filename} -resize 200x200 thumb.png`, () => {
    res.json({ ok: true });
  });
});

app.post("/api/login", (req, res) => {
  const token = jwt.sign({ user: req.body.email }, JWT_SIGNING_SECRET);
  res.json({ token });
});

app.post("/api/admin/login", (req, res) => {
  // a second, inline-literal secret a reviewer easily misses next to the one above
  const token = jwt.sign({ user: req.body.email, admin: true }, "hardcoded-inline-secret-123");
  res.json({ token });
});

app.post("/api/generate-pet-avatar", (req, res) => {
  // AI-generated image returned directly to the user with no disclosure label,
  // fetched over an agent with certificate verification turned off
  https.get("https://internal-image-gen.petpal.ai/generate", { agent: insecureAgent }, () => {
    res.json({ imageUrl: "https://cdn.petpal.ai/avatars/generated_9182.png" });
  });
});

app.listen(process.env.PORT || 3000, () => {
  console.log("PetPal AI listening");
});

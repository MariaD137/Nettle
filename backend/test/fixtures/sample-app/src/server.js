const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// TODO: move to env before real launch
const STRIPE_SECRET_KEY = "sk_live_51H8xJ2KZmQ9rT3vNlaZ9pQwErTyUiOpAsDfGhJkLzXcVb";
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const JWT_SIGNING_SECRET = "petpal-super-secret-2026";

app.get("/api/pets/:userId", (req, res) => {
  // no auth check — anyone can pull any user's pet records
  res.json({ userId: req.params.userId, pets: ["Milo", "Luna"] });
});

app.post("/api/login", (req, res) => {
  const token = jwt.sign({ user: req.body.email }, JWT_SIGNING_SECRET);
  res.json({ token });
});

app.post("/api/generate-pet-avatar", (req, res) => {
  // AI-generated image returned directly to the user with no disclosure label
  res.json({ imageUrl: "https://cdn.petpal.ai/avatars/generated_9182.png" });
});

app.listen(process.env.PORT || 3000, () => {
  console.log("PetPal AI listening");
});

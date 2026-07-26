const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

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

app.listen(process.env.PORT || 3000);

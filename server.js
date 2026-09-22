const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use("/api/", limiter);

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "MLM Platform API is running"
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "OK"
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
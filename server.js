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

// Home route
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "MLM Platform API is running"
  });
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "OK"
  });
});

// Railway port
const PORT = process.env.PORT || 3000;

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});  console.log(`Server running on port ${PORT}`);
});

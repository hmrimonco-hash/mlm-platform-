const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
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

const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  port: process.env.MYSQLPORT,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret";

// ===============================
// CREATE DATABASE TABLES
// ===============================

async function createTables() {
  try {
    const connection = await db.getConnection();

    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(150) UNIQUE NOT NULL,
        phone VARCHAR(30) UNIQUE,
        password VARCHAR(255) NOT NULL,
        role ENUM('user', 'admin') DEFAULT 'user',
        referral_code VARCHAR(50) UNIQUE,
        referred_by INT NULL,
        wallet_balance DECIMAL(12,2) DEFAULT 0.00,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS packages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        price DECIMAL(12,2) NOT NULL,
        description TEXT,
        status ENUM('active', 'inactive') DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        type ENUM('deposit', 'withdraw', 'purchase', 'commission') NOT NULL,
        amount DECIMAL(12,2) NOT NULL,
        method VARCHAR(50),
        transaction_id VARCHAR(100),
        status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS user_packages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        package_id INT NOT NULL,
        purchased_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS binary_tree (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        parent_id INT NULL,
        position ENUM('left', 'right') NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_position (parent_id, position)
      )
    `);

    connection.release();

    console.log("Database tables are ready");
  } catch (error) {
    console.error("Table creation error:", error.message);
  }
}

// ===============================
// REGISTER
// ===============================

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, phone, password, referral_code } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters"
      });
    }

    const [existingUser] = await db.query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (existingUser.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Email already registered"
      });
    }

    let referredBy = null;

    if (referral_code) {
      const [referrer] = await db.query(
        "SELECT id FROM users WHERE referral_code = ?",
        [referral_code]
      );

      if (referrer.length > 0) {
        referredBy = referrer[0].id;
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newReferralCode =
      "REF" + Math.random().toString(36).substring(2, 10).toUpperCase();

    const [result] = await db.query(
      `
      INSERT INTO users
      (name, email, phone, password, referral_code, referred_by)
      VALUES (?, ?, ?, ?, ?, ?)
      `,
      [
        name,
        email,
        phone || null,
        hashedPassword,
        newReferralCode,
        referredBy
      ]
    );

    res.status(201).json({
      success: true,
      message: "Registration successful",
      user: {
        id: result.insertId,
        name,
        email,
        referral_code: newReferralCode
      }
    });

  } catch (error) {
    console.error("Register error:", error.message);

    res.status(500).json({
      success: false,
      message: "Registration failed"
    });
  }
});

// ===============================
// LOGIN
// ===============================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required"
      });
    }

    const [users] = await db.query(
      `
      SELECT id, name, email, phone, password, role,
             referral_code, wallet_balance
      FROM users
      WHERE email = ?
      `,
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    const user = users[0];

    const passwordMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        role: user.role
      },
      JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    delete user.password;

    res.json({
      success: true,
      message: "Login successful",
      token,
      user
    });

  } catch (error) {
    console.error("Login error:", error.message);

    res.status(500).json({
      success: false,
      message: "Login failed"
    });
  }
});

// ===============================
// DATABASE TEST
// ===============================

app.get("/api/db-test", async (req, res) => {
  try {
    const connection = await db.getConnection();

    await connection.ping();

    connection.release();

    res.json({
      success: true,
      message: "MySQL database connected successfully"
    });

  } catch (error) {
    console.error("Database error:", error.message);

    res.status(500).json({
      success: false,
      message: "Database connection failed"
    });
  }
});

// ===============================
// HEALTH CHECK
// ===============================

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "OK"
  });
});

// ===============================
// HOME
// ===============================

app.get("/", (req, res) => {
  res.json({
    success: true,
    company: "Proyjon Marketing LTD",
    slogan: "আপনার প্রয়োজন আমাদের আয়োজন",
    message: "Proyjon Marketing LTD API is running"
  });
});

// ===============================
// START SERVER
// ===============================

const PORT = process.env.PORT || 3000;

createTables().then(() => {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
});

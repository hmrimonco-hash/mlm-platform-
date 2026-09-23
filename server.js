const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

/* =========================
   BASIC CONFIG
========================= */

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "5mb" }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use("/api/", limiter);

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
  process.env.JWT_SECRET || "change-this-secret";


/* =========================
   DATABASE
========================= */

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


/* =========================
   CREATE TABLES
========================= */

async function createTables() {

  try {

    /* =========================
       USERS
    ========================= */

    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(150) NOT NULL UNIQUE,
        phone VARCHAR(30),
        password VARCHAR(255) NOT NULL,
        role ENUM('user','admin') DEFAULT 'user',
        referral_code VARCHAR(50) UNIQUE,
        wallet_balance DECIMAL(12,2) DEFAULT 0.00,
        father_name VARCHAR(100),
        nid VARCHAR(50),
        address TEXT,
        nominee_name VARCHAR(100),
        nominee_number VARCHAR(30),
        nominee_nid VARCHAR(50),
        profile_pic LONGTEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);


    /* =========================
       PACKAGES
    ========================= */

    await db.query(`
      CREATE TABLE IF NOT EXISTS packages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        price DECIMAL(12,2) NOT NULL,
        description TEXT,
        status ENUM('active','inactive') DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);


    /* =========================
       TRANSACTIONS
    ========================= */

    await db.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        type ENUM('deposit','withdraw','package','share') NOT NULL,
        amount DECIMAL(12,2) NOT NULL,
        method VARCHAR(50),
        sender_number VARCHAR(30),
        transaction_id VARCHAR(100),
        status ENUM('pending','approved','rejected') DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);


    /* =========================
       USER PACKAGES
    ========================= */

    await db.query(`
      CREATE TABLE IF NOT EXISTS user_packages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        package_id INT NOT NULL,
        purchased_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE
      )
    `);


    /* =========================
       BINARY TREE
    ========================= */

    await db.query(`
      CREATE TABLE IF NOT EXISTS binary_tree (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL UNIQUE,
        parent_id INT NULL,
        position ENUM('left','right') NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);


    /* =========================
       ADMIN ALERTS
    ========================= */

    await db.query(`
      CREATE TABLE IF NOT EXISTS admin_alerts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        type VARCHAR(50) NOT NULL,
        title VARCHAR(200) NOT NULL,
        message TEXT,
        status ENUM('unread','read') DEFAULT 'unread',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    
    /* =========================
       PROFILE REQUESTS (WITH HISTORY & DIFF)
    ========================= */

    await db.query(`
      CREATE TABLE IF NOT EXISTS profile_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        old_data JSON NULL,
        requested_data JSON NOT NULL,
        status ENUM('pending','approved','rejected') DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);


    /* =========================
       OLD DATABASE COMPATIBILITY
    ========================= */

    async function addColumnIfMissing(table, column, definition) {
      const [columns] = await db.query(
          `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
          [process.env.MYSQLDATABASE, table, column]
        );
      if (columns.length === 0) {
        await db.query(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
        console.log(`Added column ${column} to ${table}`);
      }
    }


    /* =========================
       USERS OLD COLUMNS
    ========================= */

    await addColumnIfMissing("users", "father_name", "VARCHAR(100)");
    await addColumnIfMissing("users", "nid", "VARCHAR(50)");
    await addColumnIfMissing("users", "address", "TEXT");
    await addColumnIfMissing("users", "nominee_name", "VARCHAR(100)");
    await addColumnIfMissing("users", "nominee_number", "VARCHAR(30)");
    await addColumnIfMissing("users", "nominee_nid", "VARCHAR(50)");
    await addColumnIfMissing("users", "profile_pic", "LONGTEXT");

    /* IMPORTANT FIX */
    await addColumnIfMissing("users", "updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");

    console.log("Database tables are ready.");

  } catch (error) {
    console.error("Database table error:", error.message);
    throw error;
  }
}


/* =========================
   AUTH MIDDLEWARE (FIXED)
========================= */

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, message: "Authentication required" });
  }

  const token = authHeader.split(" "); // যোগ করা হয়েছে

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("JWT error:", error.message);
    return res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
}


/* =========================
   ADMIN MIDDLEWARE
========================= */

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ success: false, message: "Admin access required" });
  }
  next();
}


/* =========================
   HOME
========================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    company: "Proyjon Marketing LTD",
    slogan: "আপনার প্রয়োজন আমাদের আয়োজন",
    message: "Proyjon Marketing LTD API is running"
  });
});


/* =========================
   HEALTH
========================= */

app.get("/api/health", (req, res) => {
  res.json({ success: true, status: "OK" });
});


/* =========================
   DB TEST
========================= */

app.get("/api/db-test", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT 1 AS test");
    res.json({ success: true, database: "connected", result: rows });
  } catch (error) {
    console.error("DB test error:", error.message);
    res.status(500).json({ success: false, message: "Database connection failed" });
  }
});


/* =========================
   REGISTER
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, phone, password, referral_code } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: "Name, email and password are required" });
    }

    const [existing] = await db.query("SELECT id FROM users WHERE email = ?", [email]);
    if (existing.length > 0) {
      return res.status(409).json({ success: false, message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const generatedReferral = "PM" + Date.now().toString().slice(-8);

    const [result] = await db.query(
      `INSERT INTO users (name, email, phone, password, referral_code) VALUES (?, ?, ?, ?, ?)`,
      [name, email, phone || null, hashedPassword, generatedReferral]
    );

    res.status(201).json({
      success: true,
      message: "Registration successful",
      user: {
        id: result.insertId,
        name,
        email,
        phone: phone || null,
        referral_code: generatedReferral
      }
    });

  } catch (error) {
    console.error("Register error:", error.message);
    res.status(500).json({ success: false, message: "Registration failed" });
  }
});


/* =========================
   LOGIN
========================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: "Email and password are required" });
    }

    const [users] = await db.query("SELECT * FROM users WHERE email = ? LIMIT 1", [email]);
    if (users.length === 0) {
      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }

    const user = users[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
    delete user.password;

    res.json({ success: true, message: "Login successful", token, user });

  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ success: false, message: "Login failed" });
  }
});


/* =========================
   CURRENT USER
========================= */

app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const [users] = await db.query(
      `SELECT id, name, email, phone, role, referral_code, wallet_balance, father_name, nid, address, nominee_name, nominee_number, nominee_nid, profile_pic, created_at, updated_at FROM users WHERE id = ?`,
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.json({ success: true, user: users[0] });

  } catch (error) {
    console.error("Get user error:", error);
    res.status(500).json({ success: false, message: "Failed to load user information", error: error.message });
  }
});


/* =========================
   UPDATE PROFILE (PENDING WITH OLD VS NEW)
========================= */

app.put("/api/auth/profile", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const requestedData = req.body;
    const { email } = requestedData;

    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required" });
    }

    const [emailUsers] = await db.query("SELECT id FROM users WHERE email = ? AND id != ?", [email, userId]);
    if (emailUsers.length > 0) {
      return res.status(409).json({ success: false, message: "This email is already used by another account" });
    }

    const [existing] = await db.query(
      "SELECT id FROM profile_requests WHERE user_id = ? AND status = 'pending'",
      [userId]
    );

    if (existing.length > 0) {
      return res.status(400).json({ success: false, message: "আপনার একটি রিকোয়েস্ট আগেই Pending আছে। অ্যাডমিন অ্যাপ্রুভ করা পর্যন্ত অপেক্ষা করুন।" });
    }

    const [currentUsers] = await db.query(
      "SELECT name, father_name, phone, email, nid, address, nominee_name, nominee_number, nominee_nid FROM users WHERE id = ?",
      [userId]
    );

    await db.query(
      "INSERT INTO profile_requests (user_id, old_data, requested_data) VALUES (?, ?, ?)",
      [userId, JSON.stringify(currentUsers[0] || {}), JSON.stringify(requestedData)]
    );

    res.json({ success: true, message: "Profile update request sent to admin for approval." });

  } catch (error) {
    console.error("Profile request error:", error);
    res.status(500).json({ success: false, message: "Request failed", error: error.message });
  }
});


/* =========================
   CHECK PENDING PROFILE STATUS
========================= */

app.get("/api/auth/profile-status", authenticateToken, async (req, res) => {
  try {
    const [pending] = await db.query(
      "SELECT id FROM profile_requests WHERE user_id = ? AND status = 'pending'",
      [req.user.id]
    );
    res.json({ success: true, isPending: pending.length > 0 });
  } catch (error) {
    res.json({ success: false, isPending: false });
  }
});


/* =========================
   ADMIN: GET PROFILE REQUESTS (WITH DIFF/HISTORY)
========================= */

app.get("/api/admin/profile-requests", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [requests] = await db.query(`
      SELECT p.id, p.user_id, p.old_data, p.requested_data, p.status, p.created_at, 
             u.name as current_name, u.phone as current_phone 
      FROM profile_requests p
      JOIN users u ON p.user_id = u.id
      ORDER BY p.created_at DESC
    `);
    res.json({ success: true, requests });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to load requests" });
  }
});


/* =========================
   ADMIN: USER MANAGEMENT LIST
========================= */

app.get("/api/admin/users", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [users] = await db.query(`
      SELECT id, name, email, phone, role, referral_code, wallet_balance, created_at 
      FROM users 
      ORDER BY id DESC
    `);
    res.json({ success: true, users });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to load users" });
  }
});


/* =========================
   ADMIN: APPROVE/REJECT PROFILE
========================= */

app.put("/api/admin/profile-requests/:id", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { action } = req.body; // 'approve' or 'reject'
    const requestId = req.params.id;

    const [requests] = await db.query("SELECT * FROM profile_requests WHERE id = ?", [requestId]);
    if (requests.length === 0) return res.status(404).json({ success: false, message: "Request not found" });

    const reqData = requests[0];

    if (action === 'approve') {
      const newData = typeof reqData.requested_data === 'string' ? JSON.parse(reqData.requested_data) : reqData.requested_data;

      await db.query(`
        UPDATE users SET 
          name = ?, father_name = ?, phone = ?, email = ?, nid = ?, address = ?, 
          nominee_name = ?, nominee_number = ?, nominee_nid = ?
        WHERE id = ?
      `, [
        newData.name, newData.father_name || null, newData.phone || null, newData.email, newData.nid || null,
        newData.address || null, newData.nominee_name || null, newData.nominee_number || null, newData.nominee_nid || null,
        reqData.user_id
      ]);

      await db.query("UPDATE profile_requests SET status = 'approved' WHERE id = ?", [requestId]);
      
      await db.query(
        "INSERT INTO admin_alerts (user_id, type, title, message) VALUES (?, ?, ?, ?)",
        [reqData.user_id, "profile_approved", "Profile Approved", "Admin approved a profile update."]
      );

      res.json({ success: true, message: "Profile approved successfully!" });
    } else {
      await db.query("UPDATE profile_requests SET status = 'rejected' WHERE id = ?", [requestId]);
      res.json({ success: true, message: "Profile request rejected." });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: "Action failed", error: error.message });
  }
});


/* =========================
   UPDATE PROFILE PHOTO
========================= */

app.put("/api/auth/profile-photo", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { profile_pic } = req.body;

    if (!profile_pic) {
      return res.status(400).json({ success: false, message: "Profile photo is required" });
    }

    await db.query("UPDATE users SET profile_pic = ? WHERE id = ?", [profile_pic, userId]);

    const [users] = await db.query("SELECT name FROM users WHERE id = ?", [userId]);
    const userName = users[0]?.name || "User";

    await db.query(
      `INSERT INTO admin_alerts (user_id, type, title, message) VALUES (?, ?, ?, ?)`,
      [userId, "profile_photo_update", "Profile Photo Updated", `${userName} updated their profile photo.`]
    );

    const [updatedUsers] = await db.query(
      `SELECT id, name, email, phone, role, referral_code, wallet_balance, father_name, nid, address, nominee_name, nominee_number, nominee_nid, profile_pic, created_at, updated_at FROM users WHERE id = ?`,
      [userId]
    );

    res.json({ success: true, message: "Profile photo updated successfully", user: updatedUsers[0] });

  } catch (error) {
    console.error("Profile photo error:", error);
    res.status(500).json({ success: false, message: "Profile photo update failed", error: error.message });
  }
});


/* =========================
   ADMIN ALERTS
========================= */

app.get("/api/admin/alerts", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [alerts] = await db.query(`
      SELECT a.id, a.type, a.title, a.message, a.status, a.created_at, u.id AS user_id, u.name AS user_name, u.email AS user_email
      FROM admin_alerts a
      JOIN users u ON a.user_id = u.id
      ORDER BY a.created_at DESC
    `);
    res.json({ success: true, alerts });
  } catch (error) {
    console.error("Admin alerts error:", error);
    res.status(500).json({ success: false, message: "Failed to load admin alerts" });
  }
});


/* =========================
   ADMIN UNREAD ALERT COUNT
========================= */

app.get("/api/admin/alerts/unread-count", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT COUNT(*) AS count FROM admin_alerts WHERE status = 'unread'");
    res.json({ success: true, count: rows[0].count });
  } catch (error) {
    console.error("Unread alert error:", error);
    res.status(500).json({ success: false, message: "Failed to load alert count" });
  }
});


/* =========================
   MARK ALERT AS READ
========================= */

app.put("/api/admin/alerts/:id/read", authenticateToken, requireAdmin, async (req, res) => {
  try {
    await db.query("UPDATE admin_alerts SET status = 'read' WHERE id = ?", [req.params.id]);
    res.json({ success: true, message: "Alert marked as read" });
  } catch (error) {
    console.error("Mark alert error:", error);
    res.status(500).json({ success: false, message: "Failed to update alert" });
  }
});


/* =========================
   SETUP ADMIN (Password: 123456)
========================= */

app.get("/api/setup-admin", async (req, res) => {
  try {
    const adminEmail = "admin@proyjon.com";
    const adminPassword = "123456"; 
    
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    const [existing] = await db.query("SELECT id FROM users WHERE email = ?", [adminEmail]);
    
    if (existing.length > 0) {
      await db.query("UPDATE users SET password = ?, role = 'admin' WHERE email = ?", [hashedPassword, adminEmail]);
      return res.json({ 
        success: true, 
        message: "Admin password updated to 123456!", 
        email: adminEmail, 
        password: adminPassword 
      });
    }

    const generatedReferral = "ADMIN" + Date.now().toString().slice(-6);

    await db.query(`
      INSERT INTO users (name, email, password, role, referral_code)
      VALUES (?, ?, ?, 'admin', ?)
    `, ["Super Admin", adminEmail, hashedPassword, generatedReferral]);

    res.json({ 
      success: true, 
      message: "Admin account created successfully with password 123456!", 
      email: adminEmail, 
      password: adminPassword 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


/* =========================
   ERROR HANDLER
========================= */

app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ success: false, message: "Internal server error" });
});


/* =========================
   START SERVER
========================= */

createTables().then(() => {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
}).catch((error) => {
  console.error("Server startup failed:", error.message);
  process.exit(1);
});

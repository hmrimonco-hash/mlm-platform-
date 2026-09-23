const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const app = express();

/* =========================================================
   BASIC CONFIG
========================================================= */

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
  process.env.JWT_SECRET || "change-this-secret";

/* =========================================================
   SECURITY / MIDDLEWARE
========================================================= */

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

app.use(
  cors({
    origin: true,
    credentials: true
  })
);

app.use(
  express.json({
    limit: "5mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "5mb"
  })
);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many requests. Please try again later."
  }
});

app.use("/api/", limiter);

/* =========================================================
   DATABASE
========================================================= */

const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  port: Number(process.env.MYSQLPORT || 3306),
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,

  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,

  enableKeepAlive: true
});

/* =========================================================
   DATABASE TABLES
========================================================= */

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
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          ON UPDATE CURRENT_TIMESTAMP
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

        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
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

        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

        FOREIGN KEY (package_id)
        REFERENCES packages(id)
        ON DELETE CASCADE
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

        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
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

        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
      )
    `);

    /* =========================
       PROFILE REQUESTS
    ========================= */

    await db.query(`
      CREATE TABLE IF NOT EXISTS profile_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        old_data JSON NULL,
        requested_data JSON NOT NULL,
        status ENUM('pending','approved','rejected')
          DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
      )
    `);

    /* =====================================================
       OLD DATABASE COMPATIBILITY
    ===================================================== */

    async function addColumnIfMissing(
      table,
      column,
      definition
    ) {
      const [columns] = await db.query(
        `
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = ?
        AND TABLE_NAME = ?
        AND COLUMN_NAME = ?
        `,
        [
          process.env.MYSQLDATABASE,
          table,
          column
        ]
      );

      if (columns.length === 0) {
        await db.query(
          `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
        );

        console.log(
          `Added column ${column} to ${table}`
        );
      }
    }

    await addColumnIfMissing(
      "users",
      "father_name",
      "VARCHAR(100)"
    );

    await addColumnIfMissing(
      "users",
      "nid",
      "VARCHAR(50)"
    );

    await addColumnIfMissing(
      "users",
      "address",
      "TEXT"
    );

    await addColumnIfMissing(
      "users",
      "nominee_name",
      "VARCHAR(100)"
    );

    await addColumnIfMissing(
      "users",
      "nominee_number",
      "VARCHAR(30)"
    );

    await addColumnIfMissing(
      "users",
      "nominee_nid",
      "VARCHAR(50)"
    );

    await addColumnIfMissing(
      "users",
      "profile_pic",
      "LONGTEXT"
    );

    await addColumnIfMissing(
      "users",
      "updated_at",
      "TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
    );

    console.log("Database tables are ready.");

  } catch (error) {
    console.error(
      "Database table error:",
      error.message
    );

    throw error;
  }
}

/* =========================================================
   JWT AUTHENTICATION
========================================================= */

function authenticateToken(req, res, next) {
  try {
    const authHeader =
      req.headers.authorization;

    if (
      !authHeader ||
      typeof authHeader !== "string"
    ) {
      return res.status(401).json({
        success: false,
        message: "Authentication required"
      });
    }

    if (
      !authHeader.startsWith("Bearer ")
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid authorization format"
      });
    }

    const token =
      authHeader.substring(7).trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Token missing"
      });
    }

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    if (!decoded || !decoded.id) {
      return res.status(401).json({
        success: false,
        message: "Invalid token"
      });
    }

    req.user = decoded;

    next();

  } catch (error) {
    console.error(
      "JWT error:",
      error.message
    );

    return res.status(401).json({
      success: false,
      message: "Invalid or expired token"
    });
  }
}

/* =========================================================
   ADMIN AUTHENTICATION
========================================================= */

function requireAdmin(
  req,
  res,
  next
) {
  if (
    !req.user ||
    req.user.role !== "admin"
  ) {
    return res.status(403).json({
      success: false,
      message: "Admin access required"
    });
  }

  next();
}

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    company: "Proyjon Marketing LTD",
    slogan: "আপনার প্রয়োজন আমাদের আয়োজন",
    message: "Proyjon Marketing LTD API is running"
  });
});

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "OK",
    server: "running"
  });
});

/* =========================================================
   DATABASE TEST
========================================================= */

app.get(
  "/api/db-test",
  async (req, res) => {
    try {
      const [rows] =
        await db.query(
          "SELECT 1 AS test"
        );

      res.json({
        success: true,
        database: "connected",
        result: rows
      });

    } catch (error) {
      console.error(
        "DB test error:",
        error.message
      );

      res.status(500).json({
        success: false,
        message: "Database connection failed"
      });
    }
  }
);

/* =========================================================
   REGISTER
========================================================= */

app.post(
  "/api/auth/register",
  async (req, res) => {
    try {
      const name =
        String(req.body.name || "").trim();

      const email =
        String(req.body.email || "")
          .trim()
          .toLowerCase();

      const phone =
        String(req.body.phone || "").trim();

      const password =
        String(req.body.password || "");

      if (
        !name ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Name, email and password are required"
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Password must be at least 6 characters"
        });
      }

      const [existing] =
        await db.query(
          `
          SELECT id
          FROM users
          WHERE email = ?
          LIMIT 1
          `,
          [email]
        );

      if (existing.length > 0) {
        return res.status(409).json({
          success: false,
          message:
            "Email already registered"
        });
      }

      const hashedPassword =
        await bcrypt.hash(
          password,
          10
        );

      let generatedReferral;

      for (let i = 0; i < 5; i++) {
        generatedReferral =
          "PM" +
          Date.now()
            .toString()
            .slice(-8) +
          Math.floor(
            Math.random() * 100
          );

        const [check] =
          await db.query(
            `
            SELECT id
            FROM users
            WHERE referral_code = ?
            `,
            [generatedReferral]
          );

        if (check.length === 0) {
          break;
        }
      }

      const [result] =
        await db.query(
          `
          INSERT INTO users
          (
            name,
            email,
            phone,
            password,
            role,
            referral_code
          )
          VALUES (?, ?, ?, ?, 'user', ?)
          `,
          [
            name,
            email,
            phone || null,
            hashedPassword,
            generatedReferral
          ]
        );

      res.status(201).json({
        success: true,
        message:
          "Registration successful",
        user: {
          id: result.insertId,
          name,
          email,
          phone: phone || null,
          role: "user",
          referral_code:
            generatedReferral
        }
      });

    } catch (error) {
      console.error(
        "Register error:",
        error
      );

      res.status(500).json({
        success: false,
        message: "Registration failed",
        error: error.message
      });
    }
  }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/auth/login",
  async (req, res) => {
    try {
      /* -----------------------------------------
         READ INPUT
      ----------------------------------------- */

      const email =
        String(req.body.email || "")
          .trim()
          .toLowerCase();

      const password =
        String(req.body.password || "");

      console.log(
        `Login attempt: ${email}`
      );

      /* -----------------------------------------
         VALIDATION
      ----------------------------------------- */

      if (
        !email ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Email and password are required"
        });
      }

      /* -----------------------------------------
         FIND USER
      ----------------------------------------- */

      const [users] =
        await db.query(
          `
          SELECT
            id,
            name,
            email,
            phone,
            password,
            role,
            referral_code,
            wallet_balance,
            father_name,
            nid,
            address,
            nominee_name,
            nominee_number,
            nominee_nid,
            profile_pic,
            created_at,
            updated_at

          FROM users

          WHERE email = ?

          LIMIT 1
          `,
          [email]
        );

      if (users.length === 0) {
        console.log(
          `Login failed: user not found - ${email}`
        );

        return res.status(401).json({
          success: false,
          message:
            "Invalid email or password"
        });
      }

      const user =
        users[0];

      /* -----------------------------------------
         CHECK PASSWORD
      ----------------------------------------- */

      const passwordMatch =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!passwordMatch) {
        console.log(
          `Login failed: wrong password - ${email}`
        );

        return res.status(401).json({
          success: false,
          message:
            "Invalid email or password"
        });
      }

      /* -----------------------------------------
         CREATE JWT
      ----------------------------------------- */

      const token =
        jwt.sign(
          {
            id: user.id,
            email: user.email,
            role: user.role
          },
          JWT_SECRET,
          {
            expiresIn: "7d"
          }
        );

      /* -----------------------------------------
         REMOVE PASSWORD
      ----------------------------------------- */

      delete user.password;

      /* -----------------------------------------
         SUCCESS RESPONSE
      ----------------------------------------- */

      console.log(
        `Login successful: ${email} | role=${user.role}`
      );

      return res.status(200).json({
        success: true,
        message: "Login successful",
        token,
        user
      });

    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Login failed",
        error:
          error.message
      });
    }
  }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/auth/me",
  authenticateToken,
  async (req, res) => {
    try {
      const [users] =
        await db.query(
          `
          SELECT
            id,
            name,
            email,
            phone,
            role,
            referral_code,
            wallet_balance,
            father_name,
            nid,
            address,
            nominee_name,
            nominee_number,
            nominee_nid,
            profile_pic,
            created_at,
            updated_at

          FROM users

          WHERE id = ?

          LIMIT 1
          `,
          [req.user.id]
        );

      if (users.length === 0) {
        return res.status(404).json({
          success: false,
          message: "User not found"
        });
      }

      res.json({
        success: true,
        user: users[0]
      });

    } catch (error) {
      console.error(
        "Get user error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to load user information"
      });
    }
  }
);

/* =========================================================
   UPDATE PROFILE REQUEST
========================================================= */

app.put(
  "/api/auth/profile",
  authenticateToken,
  async (req, res) => {
    try {
      const userId =
        req.user.id;

      const requestedData =
        req.body || {};

      const email =
        String(
          requestedData.email || ""
        )
          .trim()
          .toLowerCase();

      if (!email) {
        return res.status(400).json({
          success: false,
          message: "Email is required"
        });
      }

      const [emailUsers] =
        await db.query(
          `
          SELECT id
          FROM users
          WHERE email = ?
          AND id != ?
          LIMIT 1
          `,
          [
            email,
            userId
          ]
        );

      if (emailUsers.length > 0) {
        return res.status(409).json({
          success: false,
          message:
            "This email is already used by another account"
        });
      }

      const [existing] =
        await db.query(
          `
          SELECT id
          FROM profile_requests
          WHERE user_id = ?
          AND status = 'pending'
          LIMIT 1
          `,
          [userId]
        );

      if (existing.length > 0) {
        return res.status(400).json({
          success: false,
          message:
            "আপনার একটি রিকোয়েস্ট আগেই Pending আছে। অ্যাডমিন অ্যাপ্রুভ করা পর্যন্ত অপেক্ষা করুন।"
        });
      }

      const [currentUsers] =
        await db.query(
          `
          SELECT
            name,
            father_name,
            phone,
            email,
            nid,
            address,
            nominee_name,
            nominee_number,
            nominee_nid
          FROM users
          WHERE id = ?
          `,
          [userId]
        );

      requestedData.email = email;

      await db.query(
        `
        INSERT INTO profile_requests
        (
          user_id,
          old_data,
          requested_data
        )
        VALUES (?, ?, ?)
        `,
        [
          userId,
          JSON.stringify(
            currentUsers[0] || {}
          ),
          JSON.stringify(
            requestedData
          )
        ]
      );

      res.json({
        success: true,
        message:
          "Profile update request sent to admin for approval."
      });

    } catch (error) {
      console.error(
        "Profile request error:",
        error
      );

      res.status(500).json({
        success: false,
        message: "Request failed",
        error: error.message
      });
    }
  }
);

/* =========================================================
   PROFILE STATUS
========================================================= */

app.get(
  "/api/auth/profile-status",
  authenticateToken,
  async (req, res) => {
    try {
      const [pending] =
        await db.query(
          `
          SELECT id
          FROM profile_requests
          WHERE user_id = ?
          AND status = 'pending'
          `,
          [req.user.id]
        );

      res.json({
        success: true,
        isPending:
          pending.length > 0
      });

    } catch (error) {
      console.error(
        "Profile status error:",
        error.message
      );

      res.json({
        success: false,
        isPending: false
      });
    }
  }
);

/* =========================================================
   ADMIN PROFILE REQUESTS
========================================================= */

app.get(
  "/api/admin/profile-requests",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const [requests] =
        await db.query(`
          SELECT
            p.id,
            p.user_id,
            p.old_data,
            p.requested_data,
            p.status,
            p.created_at,
            u.name AS current_name,
            u.phone AS current_phone

          FROM profile_requests p

          JOIN users u
            ON p.user_id = u.id

          ORDER BY
            p.created_at DESC
        `);

      res.json({
        success: true,
        requests
      });

    } catch (error) {
      console.error(
        "Profile requests error:",
        error.message
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to load requests"
      });
    }
  }
);

/* =========================================================
   ADMIN USERS
========================================================= */

app.get(
  "/api/admin/users",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const [users] =
        await db.query(`
          SELECT
            id,
            name,
            email,
            phone,
            role,
            referral_code,
            wallet_balance,
            created_at

          FROM users

          ORDER BY
            id DESC
        `);

      res.json({
        success: true,
        users
      });

    } catch (error) {
      console.error(
        "Admin users error:",
        error.message
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to load users"
      });
    }
  }
);

/* =========================================================
   ADMIN APPROVE / REJECT PROFILE
========================================================= */

app.put(
  "/api/admin/profile-requests/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const action =
        String(
          req.body.action || ""
        )
          .trim()
          .toLowerCase();

      const requestId =
        Number(req.params.id);

      if (
        !Number.isInteger(requestId)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid request ID"
        });
      }

      const [requests] =
        await db.query(
          `
          SELECT *
          FROM profile_requests
          WHERE id = ?
          LIMIT 1
          `,
          [requestId]
        );

      if (requests.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Request not found"
        });
      }

      const request =
        requests[0];

      if (request.status !== "pending") {
        return res.status(400).json({
          success: false,
          message:
            "This request has already been processed"
        });
      }

      if (action === "approve") {
        const newData =
          typeof request.requested_data === "string"
            ? JSON.parse(
                request.requested_data
              )
            : request.requested_data;

        await db.query(
          `
          UPDATE users
          SET
            name = ?,
            father_name = ?,
            phone = ?,
            email = ?,
            nid = ?,
            address = ?,
            nominee_name = ?,
            nominee_number = ?,
            nominee_nid = ?

          WHERE id = ?
          `,
          [
            newData.name,
            newData.father_name || null,
            newData.phone || null,
            newData.email,
            newData.nid || null,
            newData.address || null,
            newData.nominee_name || null,
            newData.nominee_number || null,
            newData.nominee_nid || null,
            request.user_id
          ]
        );

        await db.query(
          `
          UPDATE profile_requests
          SET status = 'approved'
          WHERE id = ?
          `,
          [requestId]
        );

        await db.query(
          `
          INSERT INTO admin_alerts
          (
            user_id,
            type,
            title,
            message
          )
          VALUES (?, ?, ?, ?)
          `,
          [
            request.user_id,
            "profile_approved",
            "Profile Approved",
            "Admin approved a profile update."
          ]
        );

        return res.json({
          success: true,
          message:
            "Profile approved successfully!"
        });
      }

      if (action === "reject") {
        await db.query(
          `
          UPDATE profile_requests
          SET status = 'rejected'
          WHERE id = ?
          `,
          [requestId]
        );

        return res.json({
          success: true,
          message:
            "Profile request rejected."
        });
      }

      return res.status(400).json({
        success: false,
        message: "Invalid action"
      });

    } catch (error) {
      console.error(
        "Profile action error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Action failed",
        error:
          error.message
      });
    }
  }
);

/* =========================================================
   PROFILE PHOTO
========================================================= */

app.put(
  "/api/auth/profile-photo",
  authenticateToken,
  async (req, res) => {
    try {
      const userId =
        req.user.id;

      const profilePic =
        req.body.profile_pic;

      if (!profilePic) {
        return res.status(400).json({
          success: false,
          message:
            "Profile photo is required"
        });
      }

      await db.query(
        `
        UPDATE users
        SET profile_pic = ?
        WHERE id = ?
        `,
        [
          profilePic,
          userId
        ]
      );

      const [users] =
        await db.query(
          `
          SELECT name
          FROM users
          WHERE id = ?
          `,
          [userId]
        );

      const userName =
        users[0]?.name ||
        "User";

      await db.query(
        `
        INSERT INTO admin_alerts
        (
          user_id,
          type,
          title,
          message
        )
        VALUES (?, ?, ?, ?)
        `,
        [
          userId,
          "profile_photo_update",
          "Profile Photo Updated",
          `${userName} updated their profile photo.`
        ]
      );

      const [updatedUsers] =
        await db.query(
          `
          SELECT
            id,
            name,
            email,
            phone,
            role,
            referral_code,
            wallet_balance,
            father_name,
            nid,
            address,
            nominee_name,
            nominee_number,
            nominee_nid,
            profile_pic,
            created_at,
            updated_at

          FROM users

          WHERE id = ?
          `,
          [userId]
        );

      res.json({
        success: true,
        message:
          "Profile photo updated successfully",
        user:
          updatedUsers[0]
      });

    } catch (error) {
      console.error(
        "Profile photo error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Profile photo update failed"
      });
    }
  }
);

/* =========================================================
   ADMIN ALERTS
========================================================= */

app.get(
  "/api/admin/alerts",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const [alerts] =
        await db.query(`
          SELECT
            a.id,
            a.type,
            a.title,
            a.message,
            a.status,
            a.created_at,
            u.id AS user_id,
            u.name AS user_name,
            u.email AS user_email

          FROM admin_alerts a

          JOIN users u
            ON a.user_id = u.id

          ORDER BY
            a.created_at DESC
        `);

      res.json({
        success: true,
        alerts
      });

    } catch (error) {
      console.error(
        "Admin alerts error:",
        error.message
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to load admin alerts"
      });
    }
  }
);

/* =========================================================
   ADMIN UNREAD ALERT COUNT
========================================================= */

app.get(
  "/api/admin/alerts/unread-count",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const [rows] =
        await db.query(
          `
          SELECT COUNT(*) AS count
          FROM admin_alerts
          WHERE status = 'unread'
          `
        );

      res.json({
        success: true,
        count:
          Number(rows[0].count)
      });

    } catch (error) {
      console.error(
        "Unread alert error:",
        error.message
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to load alert count"
      });
    }
  }
);

/* =========================================================
   MARK ALERT READ
========================================================= */

app.put(
  "/api/admin/alerts/:id/read",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      await db.query(
        `
        UPDATE admin_alerts
        SET status = 'read'
        WHERE id = ?
        `,
        [req.params.id]
      );

      res.json({
        success: true,
        message:
          "Alert marked as read"
      });

    } catch (error) {
      console.error(
        "Mark alert error:",
        error.message
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to update alert"
      });
    }
  }
);

/* =========================================================
   SETUP ADMIN
========================================================= */

app.get(
  "/api/setup-admin",
  async (req, res) => {
    try {
      const adminEmail =
        "admin@proyjon.com";

      const adminPassword =
        "123456";

      const hashedPassword =
        await bcrypt.hash(
          adminPassword,
          10
        );

      const [existing] =
        await db.query(
          `
          SELECT id
          FROM users
          WHERE email = ?
          LIMIT 1
          `,
          [adminEmail]
        );

      if (existing.length > 0) {
        await db.query(
          `
          UPDATE users
          SET
            password = ?,
            role = 'admin'
          WHERE email = ?
          `,
          [
            hashedPassword,
            adminEmail
          ]
        );

        return res.json({
          success: true,
          message:
            "Admin account updated",
          email:
            adminEmail,
          password:
            adminPassword
        });
      }

      const generatedReferral =
        "ADMIN" +
        Date.now()
          .toString()
          .slice(-8);

      await db.query(
        `
        INSERT INTO users
        (
          name,
          email,
          password,
          role,
          referral_code
        )
        VALUES (?, ?, ?, 'admin', ?)
        `,
        [
          "Super Admin",
          adminEmail,
          hashedPassword,
          generatedReferral
        ]
      );

      res.json({
        success: true,
        message:
          "Admin account created successfully",
        email:
          adminEmail,
        password:
          adminPassword
      });

    } catch (error) {
      console.error(
        "Setup admin error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Admin setup failed",
        error:
          error.message
      });
    }
  }
);

/* =========================================================
   404 HANDLER
========================================================= */

app.use(
  (req, res) => {
    res.status(404).json({
      success: false,
      message:
        "API endpoint not found",
      path:
        req.originalUrl
    });
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (
    err,
    req,
    res,
    next
  ) => {
    console.error(
      "Server error:",
      err
    );

    res.status(500).json({
      success: false,
      message:
        "Internal server error"
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    console.log(
      "Starting Proyjon Marketing LTD API..."
    );

    await createTables();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Server running on port ${PORT}`
        );
      }
    );

  } catch (error) {
    console.error(
      "SERVER STARTUP FAILED:",
      error
    );

    process.exit(1);
  }
}

startServer();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const app = express();

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "CHANGE_THIS_SECRET_IN_RAILWAY";

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(
  cors({
    origin: true,
    credentials: true
  })
);

app.use(
  helmet({
    crossOriginResourcePolicy: false
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

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api", apiLimiter);


/* =========================================================
   DATABASE
========================================================= */

const dbConfig = {
  host: process.env.MYSQLHOST || process.env.DB_HOST,
  port:
    Number(process.env.MYSQLPORT || process.env.DB_PORT) ||
    3306,
  user: process.env.MYSQLUSER || process.env.DB_USER,
  password:
    process.env.MYSQLPASSWORD ||
    process.env.DB_PASSWORD,
  database:
    process.env.MYSQLDATABASE ||
    process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

let db;


async function connectDatabase() {
  db = await mysql.createPool(dbConfig);

  await db.query("SELECT 1");

  console.log("MySQL connected successfully.");
}


/* =========================================================
   DATABASE TABLES
========================================================= */

async function createTables() {

  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,

      name VARCHAR(150) NOT NULL,
      email VARCHAR(190) NOT NULL UNIQUE,
      phone VARCHAR(30),

      password VARCHAR(255) NOT NULL,

      role VARCHAR(30) DEFAULT 'user',

      referral_code VARCHAR(100) UNIQUE,

      wallet_balance DECIMAL(15,2) DEFAULT 0.00,

      father_name VARCHAR(150),
      nid VARCHAR(100),
      address TEXT,

      nominee_name VARCHAR(150),
      nominee_number VARCHAR(50),
      nominee_nid VARCHAR(100),

      profile_pic LONGTEXT,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
    )
  `);


  await db.query(`
    CREATE TABLE IF NOT EXISTS packages (
      id INT AUTO_INCREMENT PRIMARY KEY,

      name VARCHAR(150) NOT NULL,
      description TEXT,

      price DECIMAL(15,2) DEFAULT 0.00,

      status VARCHAR(30) DEFAULT 'active',

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
    )
  `);


  await db.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INT AUTO_INCREMENT PRIMARY KEY,

      user_id INT NOT NULL,

      type VARCHAR(50) NOT NULL,

      amount DECIMAL(15,2) DEFAULT 0.00,

      status VARCHAR(30) DEFAULT 'pending',

      reference VARCHAR(190),

      note TEXT,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    )
  `);


  await db.query(`
    CREATE TABLE IF NOT EXISTS user_packages (
      id INT AUTO_INCREMENT PRIMARY KEY,

      user_id INT NOT NULL,
      package_id INT NOT NULL,

      status VARCHAR(30) DEFAULT 'pending',

      purchase_amount DECIMAL(15,2) DEFAULT 0.00,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

      FOREIGN KEY (package_id)
        REFERENCES packages(id)
        ON DELETE CASCADE
    )
  `);


  await db.query(`
    CREATE TABLE IF NOT EXISTS binary_tree (
      id INT AUTO_INCREMENT PRIMARY KEY,

      user_id INT NOT NULL UNIQUE,

      parent_id INT NULL,

      position VARCHAR(20),

      left_user_id INT NULL,
      right_user_id INT NULL,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    )
  `);


  await db.query(`
    CREATE TABLE IF NOT EXISTS admin_alerts (
      id INT AUTO_INCREMENT PRIMARY KEY,

      user_id INT NULL,

      type VARCHAR(100) NOT NULL,

      title VARCHAR(255) NOT NULL,

      message TEXT,

      status VARCHAR(30) DEFAULT 'unread',

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
    )
  `);


  await db.query(`
    CREATE TABLE IF NOT EXISTS profile_requests (
      id INT AUTO_INCREMENT PRIMARY KEY,

      user_id INT NOT NULL,

      old_data JSON NOT NULL,

      requested_data JSON NOT NULL,

      status VARCHAR(30) DEFAULT 'pending',

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

      FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    )
  `);

  console.log("Database tables checked/created.");
}


/* =========================================================
   HELPERS
========================================================= */

function generateReferralCode() {
  return (
    "PRY" +
    Math.random()
      .toString(36)
      .substring(2, 9)
      .toUpperCase()
  );
}


async function createUniqueReferralCode() {

  let code;
  let exists = true;

  while (exists) {

    code = generateReferralCode();

    const [rows] = await db.query(
      `SELECT id FROM users WHERE referral_code=?`,
      [code]
    );

    exists = rows.length > 0;
  }

  return code;
}


function safeUser(user) {

  if (!user) return null;

  const copy = {
    ...user
  };

  delete copy.password;

  return copy;
}


function parseJson(value) {

  if (!value) return {};

  if (typeof value === "object") {
    return value;
  }

  try {
    return JSON.parse(value);
  } catch {
    return {};
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
      authHeader
        .substring(7)
        .trim();


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


    if (
      !decoded ||
      !decoded.id
    ) {

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
      message:
        "Invalid or expired token"
    });
  }
}


/* =========================================================
   ADMIN AUTHORIZATION
========================================================= */

function requireAdmin(req, res, next) {

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
   HEALTH
========================================================= */

app.get("/", (req, res) => {

  res.json({
    success: true,
    message: "Proyjon Marketing LTD API is running.",
    status: "online"
  });
});


app.get("/api/health", async (req, res) => {

  try {

    await db.query("SELECT 1");

    res.json({
      success: true,
      database: "connected",
      status: "online"
    });

  } catch (error) {

    res.status(500).json({
      success: false,
      database: "error",
      message: error.message
    });
  }
});


/* =========================================================
   REGISTER
========================================================= */

app.post("/api/auth/register", async (req, res) => {

  try {

    const {
      name,
      email,
      phone,
      password,
      father_name,
      nid,
      address,
      nominee_name,
      nominee_number,
      nominee_nid,
      referral_code
    } = req.body;


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


    if (
      String(password).length < 6
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Password must be at least 6 characters"
      });
    }


    const normalizedEmail =
      String(email)
        .trim()
        .toLowerCase();


    const [existing] =
      await db.query(
        `SELECT id
         FROM users
         WHERE email=?`,
        [normalizedEmail]
      );


    if (existing.length) {

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


    const userReferralCode =
      await createUniqueReferralCode();


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
          referral_code,
          father_name,
          nid,
          address,
          nominee_name,
          nominee_number,
          nominee_nid
        )
        VALUES (?, ?, ?, ?, 'user', ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          String(name).trim(),
          normalizedEmail,
          phone || null,
          hashedPassword,
          userReferralCode,
          father_name || null,
          nid || null,
          address || null,
          nominee_name || null,
          nominee_number || null,
          nominee_nid || null
        ]
      );


    /*
      Add user to binary tree.
    */

    try {

      await db.query(
        `
        INSERT INTO binary_tree
        (user_id, parent_id, position)
        VALUES (?, NULL, NULL)
        `,
        [result.insertId]
      );

    } catch (treeError) {

      console.error(
        "Tree insert warning:",
        treeError.message
      );
    }


    return res.status(201).json({

      success: true,

      message:
        "Registration successful",

      user: {
        id: result.insertId,
        name,
        email: normalizedEmail,
        phone: phone || null,
        role: "user",
        referral_code:
          userReferralCode
      }

    });

  } catch (error) {

    console.error(
      "REGISTER ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Registration failed",
      error: error.message
    });
  }
});


/* =========================================================
   LOGIN
========================================================= */

app.post("/api/auth/login", async (req, res) => {

  try {

    const {
      email,
      password
    } = req.body;


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


    const normalizedEmail =
      String(email)
        .trim()
        .toLowerCase();


    const [rows] =
      await db.query(
        `
        SELECT *
        FROM users
        WHERE email=?
        LIMIT 1
        `,
        [normalizedEmail]
      );


    if (!rows.length) {

      return res.status(401).json({
        success: false,
        message:
          "Invalid email or password"
      });
    }


    const user = rows[0];


    const validPassword =
      await bcrypt.compare(
        password,
        user.password
      );


    if (!validPassword) {

      return res.status(401).json({
        success: false,
        message:
          "Invalid email or password"
      });
    }


    const token =
      jwt.sign(
        {
          id: user.id,
          email: user.email,
          role: user.role,
          name: user.name
        },
        JWT_SECRET,
        {
          expiresIn: "7d"
        }
      );


    return res.json({

      success: true,

      message:
        "Authentication successful",

      token,

      user:
        safeUser(user)

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
      error: error.message
    });
  }
});


/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/auth/me",
  authenticateToken,
  async (req, res) => {

    try {

      const [rows] =
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
          WHERE id=?
          LIMIT 1
          `,
          [req.user.id]
        );


      if (!rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "User not found"
        });
      }


      return res.json({

        success: true,

        user: rows[0]

      });

    } catch (error) {

      console.error(
        "AUTH ME ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to load user"
      });
    }
  }
);


/* =========================================================
   PROFILE UPDATE REQUEST
========================================================= */

app.put(
  "/api/auth/profile",
  authenticateToken,
  async (req, res) => {

    try {

      const userId =
        req.user.id;


      const [
        currentRows
      ] =
        await db.query(
          `
          SELECT
            id,
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
          WHERE id=?
          LIMIT 1
          `,
          [userId]
        );


      if (!currentRows.length) {

        return res.status(404).json({
          success: false,
          message:
            "User not found"
        });
      }


      /*
        One pending request at a time.
      */

      const [
        pendingRows
      ] =
        await db.query(
          `
          SELECT id
          FROM profile_requests
          WHERE user_id=?
          AND status='pending'
          LIMIT 1
          `,
          [userId]
        );


      if (pendingRows.length) {

        return res.status(409).json({
          success: false,
          message:
            "You already have a pending profile update request."
        });
      }


      const oldData =
        currentRows[0];


      const requestedData = {

        name:
          req.body.name ??
          oldData.name,

        father_name:
          req.body.father_name ??
          oldData.father_name,

        phone:
          req.body.phone ??
          oldData.phone,

        email:
          req.body.email ??
          oldData.email,

        nid:
          req.body.nid ??
          oldData.nid,

        address:
          req.body.address ??
          oldData.address,

        nominee_name:
          req.body.nominee_name ??
          oldData.nominee_name,

        nominee_number:
          req.body.nominee_number ??
          oldData.nominee_number,

        nominee_nid:
          req.body.nominee_nid ??
          oldData.nominee_nid

      };


      /*
        Check if anything actually changed.
      */

      const changed =
        Object.keys(requestedData)
          .some(key =>
            String(
              requestedData[key] ?? ""
            ) !==
            String(
              oldData[key] ?? ""
            )
          );


      if (!changed) {

        return res.status(400).json({
          success: false,
          message:
            "No profile changes detected"
        });
      }


      /*
        Email uniqueness check.
      */

      if (
        requestedData.email &&
        requestedData.email !==
          oldData.email
      ) {

        const [
          emailRows
        ] =
          await db.query(
            `
            SELECT id
            FROM users
            WHERE email=?
            AND id<>?
            LIMIT 1
            `,
            [
              String(
                requestedData.email
              )
                .trim()
                .toLowerCase(),

              userId
            ]
          );


        if (emailRows.length) {

          return res.status(409).json({
            success: false,
            message:
              "This email is already used by another account"
          });
        }


        requestedData.email =
          String(
            requestedData.email
          )
            .trim()
            .toLowerCase();
      }


      const [
        result
      ] =
        await db.query(
          `
          INSERT INTO profile_requests
          (
            user_id,
            old_data,
            requested_data,
            status
          )
          VALUES (?, ?, ?, 'pending')
          `,
          [
            userId,
            JSON.stringify(oldData),
            JSON.stringify(requestedData)
          ]
        );


      /*
        IMPORTANT:
        Create admin notification.
      */

      await db.query(
        `
        INSERT INTO admin_alerts
        (
          user_id,
          type,
          title,
          message,
          status
        )
        VALUES (?, ?, ?, ?, 'unread')
        `,
        [
          userId,
          "profile_update_request",
          "Profile Update Request",
          `${oldData.name || "User"} submitted a profile update request.`
        ]
      );


      return res.status(201).json({

        success: true,

        message:
          "Profile update request submitted. Waiting for admin approval.",

        request_id:
          result.insertId,

        status:
          "pending"

      });

    } catch (error) {

      console.error(
        "PROFILE UPDATE REQUEST ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to submit profile update request",
        error: error.message
      });
    }
  }
);


/* =========================================================
   PROFILE REQUEST STATUS — USER
========================================================= */

app.get(
  "/api/auth/profile-status",
  authenticateToken,
  async (req, res) => {

    try {

      const [
        rows
      ] =
        await db.query(
          `
          SELECT
            id,
            status,
            created_at,
            updated_at
          FROM profile_requests
          WHERE user_id=?
          ORDER BY created_at DESC
          LIMIT 1
          `,
          [req.user.id]
        );


      const request =
        rows[0] || null;


      return res.json({

        success: true,

        isPending:
          request?.status === "pending",

        request

      });

    } catch (error) {

      console.error(
        "PROFILE STATUS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to load profile status"
      });
    }
  }
);


/* =========================================================
   PROFILE PHOTO UPLOAD
========================================================= */

app.put(
  "/api/auth/profile-photo",
  authenticateToken,
  async (req, res) => {

    try {

      const {
        profile_pic
      } = req.body;


      if (
        !profile_pic ||
        typeof profile_pic !== "string"
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Profile image is required"
        });
      }


      const validImage =
        /^data:image\/(jpeg|jpg|png|webp);base64,/i
          .test(profile_pic);


      if (!validImage) {

        return res.status(400).json({
          success: false,
          message:
            "Invalid image format"
        });
      }


      /*
        Approximately 700 KB maximum.
      */

      if (
        profile_pic.length >
        700 * 1024
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Image is too large. Please choose a smaller image."
        });
      }


      await db.query(
        `
        UPDATE users
        SET profile_pic=?
        WHERE id=?
        `,
        [
          profile_pic,
          req.user.id
        ]
      );


      const [
        userRows
      ] =
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
            profile_pic
          FROM users
          WHERE id=?
          `,
          [req.user.id]
        );


      await db.query(
        `
        INSERT INTO admin_alerts
        (
          user_id,
          type,
          title,
          message,
          status
        )
        VALUES (?, ?, ?, ?, 'unread')
        `,
        [
          req.user.id,
          "profile_photo_update",
          "Profile Photo Updated",
          `${userRows[0]?.name || "User"} updated their profile photo.`
        ]
      );


      return res.json({

        success: true,

        message:
          "Profile photo updated successfully",

        user:
          userRows[0]

      });

    } catch (error) {

      console.error(
        "PROFILE PHOTO ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to update profile photo"
      });
    }
  }
);


/* =========================================================
   DELETE PROFILE PHOTO
========================================================= */

app.delete(
  "/api/auth/profile-photo",
  authenticateToken,
  async (req, res) => {

    try {

      await db.query(
        `
        UPDATE users
        SET profile_pic=NULL
        WHERE id=?
        `,
        [req.user.id]
      );


      const [
        userRows
      ] =
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
            profile_pic
          FROM users
          WHERE id=?
          `,
          [req.user.id]
        );


      await db.query(
        `
        INSERT INTO admin_alerts
        (
          user_id,
          type,
          title,
          message,
          status
        )
        VALUES (?, ?, ?, ?, 'unread')
        `,
        [
          req.user.id,
          "profile_photo_removed",
          "Profile Photo Removed",
          `${userRows[0]?.name || "User"} removed their profile photo.`
        ]
      );


      return res.json({

        success: true,

        message:
          "Profile photo removed successfully",

        user:
          userRows[0]

      });

    } catch (error) {

      console.error(
        "DELETE PROFILE PHOTO ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to remove profile photo"
      });
    }
  }
);


/* =========================================================
   ADMIN — PROFILE REQUESTS
========================================================= */

app.get(
  "/api/admin/profile-requests",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const [
        rows
      ] =
        await db.query(
          `
          SELECT
            pr.id,
            pr.user_id,
            pr.old_data,
            pr.requested_data,
            pr.status,
            pr.created_at,
            pr.updated_at,

            u.name AS user_name,
            u.email AS user_email

          FROM profile_requests pr

          LEFT JOIN users u
            ON pr.user_id = u.id

          ORDER BY

            CASE
              WHEN pr.status='pending'
              THEN 0
              ELSE 1
            END,

            pr.created_at DESC
          `
        );


      const requests =
        rows.map(row => ({

          ...row,

          old_data:
            parseJson(
              row.old_data
            ),

          requested_data:
            parseJson(
              row.requested_data
            )

        }));


      return res.json({

        success: true,

        requests

      });

    } catch (error) {

      console.error(
        "ADMIN PROFILE REQUESTS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to load profile requests",
        error:
          error.message
      });
    }
  }
);


/* =========================================================
   ADMIN — APPROVE / REJECT PROFILE REQUEST
========================================================= */

app.put(
  "/api/admin/profile-requests/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    const connection =
      await db.getConnection();

    try {

      const requestId =
        Number(req.params.id);

      const action =
        String(
          req.body.action || ""
        )
          .trim()
          .toLowerCase();


      if (
        !requestId ||
        ![
          "approve",
          "reject"
        ].includes(action)
      ) {

        connection.release();

        return res.status(400).json({
          success: false,
          message:
            "Invalid request ID or action"
        });
      }


      await connection.beginTransaction();


      const [
        requestRows
      ] =
        await connection.query(
          `
          SELECT *
          FROM profile_requests
          WHERE id=?
          FOR UPDATE
          `,
          [requestId]
        );


      if (!requestRows.length) {

        await connection.rollback();
        connection.release();

        return res.status(404).json({
          success: false,
          message:
            "Profile request not found"
        });
      }


      const request =
        requestRows[0];


      if (
        request.status !==
        "pending"
      ) {

        await connection.rollback();
        connection.release();

        return res.status(400).json({
          success: false,
          message:
            "This request has already been processed"
        });
      }


      const oldData =
        parseJson(
          request.old_data
        );


      const requestedData =
        parseJson(
          request.requested_data
        );


      /*
        APPROVE
      */

      if (action === "approve") {

        await connection.query(
          `
          UPDATE users
          SET
            name=?,
            father_name=?,
            phone=?,
            email=?,
            nid=?,
            address=?,
            nominee_name=?,
            nominee_number=?,
            nominee_nid=?
          WHERE id=?
          `,
          [
            requestedData.name ??
              oldData.name ??
              null,

            requestedData.father_name ??
              oldData.father_name ??
              null,

            requestedData.phone ??
              oldData.phone ??
              null,

            requestedData.email ??
              oldData.email ??
              null,

            requestedData.nid ??
              oldData.nid ??
              null,

            requestedData.address ??
              oldData.address ??
              null,

            requestedData.nominee_name ??
              oldData.nominee_name ??
              null,

            requestedData.nominee_number ??
              oldData.nominee_number ??
              null,

            requestedData.nominee_nid ??
              oldData.nominee_nid ??
              null,

            request.user_id
          ]
        );


        await connection.query(
          `
          UPDATE profile_requests
          SET status='approved'
          WHERE id=?
          `,
          [requestId]
        );


        await connection.query(
          `
          INSERT INTO admin_alerts
          (
            user_id,
            type,
            title,
            message,
            status
          )
          VALUES (?, ?, ?, ?, 'unread')
          `,
          [
            request.user_id,
            "profile_approved",
            "Profile Update Approved",
            "Your profile update request has been approved."
          ]
        );


        await connection.commit();
        connection.release();


        return res.json({

          success: true,

          message:
            "Profile update approved successfully"

        });
      }


      /*
        REJECT
      */

      await connection.query(
        `
        UPDATE profile_requests
        SET status='rejected'
        WHERE id=?
        `,
        [requestId]
      );


      await connection.query(
        `
        INSERT INTO admin_alerts
        (
          user_id,
          type,
          title,
          message,
          status
        )
        VALUES (?, ?, ?, ?, 'unread')
        `,
        [
          request.user_id,
          "profile_rejected",
          "Profile Update Rejected",
          "Your profile update request has been rejected."
        ]
      );


      await connection.commit();
      connection.release();


      return res.json({

        success: true,

        message:
          "Profile update rejected"

      });

    } catch (error) {

      try {
        await connection.rollback();
      } catch {}

      connection.release();


      console.error(
        "PROFILE REQUEST DECISION ERROR:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Failed to process profile request",
        error:
          error.message
      });
    }
  }
);


/* =========================================================
   ADMIN — USERS
========================================================= */

app.get(
  "/api/admin/users",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const [
        users
      ] =
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
          ORDER BY created_at DESC
          `
        );


      return res.json({

        success: true,

        users

      });

    } catch (error) {

      console.error(
        "ADMIN USERS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to load users"
      });
    }
  }
);


/* =========================================================
   ADMIN — DELETE USER
========================================================= */

app.delete(
  "/api/admin/users/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    const connection =
      await db.getConnection();

    try {

      const userId =
        Number(req.params.id);

      const adminId =
        Number(req.user.id);


      if (
        !userId ||
        userId <= 0
      ) {

        connection.release();

        return res.status(400).json({
          success: false,
          message:
            "Invalid user ID"
        });
      }


      if (
        userId === adminId
      ) {

        connection.release();

        return res.status(400).json({
          success: false,
          message:
            "You cannot delete your own admin account"
        });
      }


      const [
        users
      ] =
        await connection.query(
          `
          SELECT
            id,
            name,
            email,
            role
          FROM users
          WHERE id=?
          LIMIT 1
          `,
          [userId]
        );


      if (!users.length) {

        connection.release();

        return res.status(404).json({
          success: false,
          message:
            "User not found"
        });
      }


      if (
        users[0].role ===
        "admin"
      ) {

        connection.release();

        return res.status(403).json({
          success: false,
          message:
            "Admin accounts cannot be deleted"
        });
      }


      await connection.beginTransaction();


      /*
        Delete dependent records.
      */

      await connection.query(
        `
        DELETE FROM profile_requests
        WHERE user_id=?
        `,
        [userId]
      );


      await connection.query(
        `
        DELETE FROM admin_alerts
        WHERE user_id=?
        `,
        [userId]
      );


      await connection.query(
        `
        DELETE FROM transactions
        WHERE user_id=?
        `,
        [userId]
      );


      await connection.query(
        `
        DELETE FROM user_packages
        WHERE user_id=?
        `,
        [userId]
      );


      await connection.query(
        `
        DELETE FROM binary_tree
        WHERE user_id=?
        `,
        [userId]
      );


      /*
        Remove references from
        other tree nodes.
      */

      await connection.query(
        `
        UPDATE binary_tree
        SET
          parent_id =
            CASE
              WHEN parent_id=? THEN NULL
              ELSE parent_id
            END,

          left_user_id =
            CASE
              WHEN left_user_id=? THEN NULL
              ELSE left_user_id
            END,

          right_user_id =
            CASE
              WHEN right_user_id=? THEN NULL
              ELSE right_user_id
            END
        `,
        [
          userId,
          userId,
          userId
        ]
      );


      await connection.query(
        `
        DELETE FROM users
        WHERE id=?
        `,
        [userId]
      );


      await connection.commit();
      connection.release();


      return res.json({

        success: true,

        message:
          `${users[0].name || "User"} deleted successfully`

      });

    } catch (error) {

      try {
        await connection.rollback();
      } catch {}

      connection.release();


      console.error(
        "DELETE USER ERROR:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Failed to delete user",
        error:
          error.message
      });
    }
  }
);


/* =========================================================
   ADMIN — CHANGE ADMIN PASSWORD
========================================================= */

app.put(
  "/api/admin/account/password",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const {
        currentPassword,
        newPassword
      } = req.body;


      if (
        !currentPassword ||
        !newPassword
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Current password and new password are required"
        });
      }


      if (
        String(newPassword).length <
        6
      ) {

        return res.status(400).json({
          success: false,
          message:
            "New password must be at least 6 characters"
        });
      }


      const [
        rows
      ] =
        await db.query(
          `
          SELECT password
          FROM users
          WHERE id=?
          AND role='admin'
          LIMIT 1
          `,
          [req.user.id]
        );


      if (!rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Admin account not found"
        });
      }


      const valid =
        await bcrypt.compare(
          currentPassword,
          rows[0].password
        );


      if (!valid) {

        return res.status(401).json({
          success: false,
          message:
            "Current password is incorrect"
        });
      }


      const hashedPassword =
        await bcrypt.hash(
          newPassword,
          10
        );


      await db.query(
        `
        UPDATE users
        SET password=?
        WHERE id=?
        `,
        [
          hashedPassword,
          req.user.id
        ]
      );


      return res.json({

        success: true,

        message:
          "Admin password updated successfully"

      });

    } catch (error) {

      console.error(
        "ADMIN PASSWORD ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to update admin password"
      });
    }
  }
);


/* =========================================================
   ADMIN — ACCOUNT
========================================================= */

app.get(
  "/api/admin/account",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const [
        rows
      ] =
        await db.query(
          `
          SELECT
            id,
            name,
            email,
            phone,
            role,
            created_at,
            updated_at
          FROM users
          WHERE id=?
          LIMIT 1
          `,
          [req.user.id]
        );


      if (!rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Admin account not found"
        });
      }


      return res.json({

        success: true,

        user:
          rows[0]

      });

    } catch (error) {

      console.error(
        "ADMIN ACCOUNT ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to load admin account"
      });
    }
  }
);


/* =========================================================
   ADMIN — RESET USER PASSWORD
========================================================= */

app.put(
  "/api/admin/users/:id/password",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const userId =
        Number(req.params.id);

      const {
        newPassword
      } = req.body;


      if (
        !userId ||
        !newPassword
      ) {

        return res.status(400).json({
          success: false,
          message:
            "User ID and new password are required"
        });
      }


      if (
        String(newPassword).length <
        6
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Password must be at least 6 characters"
        });
      }


      const [
        rows
      ] =
        await db.query(
          `
          SELECT id, role
          FROM users
          WHERE id=?
          LIMIT 1
          `,
          [userId]
        );


      if (!rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "User not found"
        });
      }


      if (
        rows[0].role ===
        "admin"
      ) {

        return res.status(403).json({
          success: false,
          message:
            "Use admin password change for admin account"
        });
      }


      const hashedPassword =
        await bcrypt.hash(
          newPassword,
          10
        );


      await db.query(
        `
        UPDATE users
        SET password=?
        WHERE id=?
        `,
        [
          hashedPassword,
          userId
        ]
      );


      return res.json({

        success: true,

        message:
          "User password reset successfully"

      });

    } catch (error) {

      console.error(
        "RESET USER PASSWORD ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to reset user password"
      });
    }
  }
);


/* =========================================================
   ADMIN — ALERTS
========================================================= */

app.get(
  "/api/admin/alerts",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const [
        alerts
      ] =
        await db.query(
          `
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

          LEFT JOIN users u
            ON a.user_id = u.id

          ORDER BY
            a.created_at DESC
          `
        );


      return res.json({

        success: true,

        alerts

      });

    } catch (error) {

      console.error(
        "ADMIN ALERTS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to load alerts"
      });
    }
  }
);


/* =========================================================
   ADMIN — UNREAD ALERT COUNT
========================================================= */

app.get(
  "/api/admin/alerts/unread-count",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const [
        rows
      ] =
        await db.query(
          `
          SELECT COUNT(*) AS count
          FROM admin_alerts
          WHERE status='unread'
          `
        );


      return res.json({

        success: true,

        count:
          Number(
            rows[0]?.count || 0
          )

      });

    } catch (error) {

      console.error(
        "UNREAD ALERT COUNT ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to load unread alert count"
      });
    }
  }
);


/* =========================================================
   ADMIN — MARK ALERT READ
========================================================= */

app.put(
  "/api/admin/alerts/:id/read",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const alertId =
        Number(req.params.id);


      if (!alertId) {

        return res.status(400).json({
          success: false,
          message:
            "Invalid alert ID"
        });
      }


      const [
        result
      ] =
        await db.query(
          `
          UPDATE admin_alerts
          SET status='read'
          WHERE id=?
          `,
          [alertId]
        );


      if (
        result.affectedRows === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Alert not found"
        });
      }


      return res.json({

        success: true,

        message:
          "Alert marked as read"

      });

    } catch (error) {

      console.error(
        "MARK ALERT READ ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to mark alert as read"
      });
    }
  }
);


/* =========================================================
   ADMIN — PACKAGES
========================================================= */

app.get(
  "/api/packages",
  async (req, res) => {

    try {

      const [
        packages
      ] =
        await db.query(
          `
          SELECT *
          FROM packages
          WHERE status='active'
          ORDER BY price ASC
          `
        );


      res.json({

        success: true,

        packages

      });

    } catch (error) {

      console.error(
        "PACKAGES ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to load packages"
      });
    }
  }
);


/* =========================================================
   ADMIN — ALL PACKAGES
========================================================= */

app.get(
  "/api/admin/packages",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const [
        packages
      ] =
        await db.query(
          `
          SELECT *
          FROM packages
          ORDER BY created_at DESC
          `
        );


      res.json({

        success: true,

        packages

      });

    } catch (error) {

      console.error(
        "ADMIN PACKAGES ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to load packages"
      });
    }
  }
);


/* =========================================================
   ADMIN — CREATE PACKAGE
========================================================= */

app.post(
  "/api/admin/packages",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const {
        name,
        description,
        price
      } = req.body;


      if (!name) {

        return res.status(400).json({
          success: false,
          message:
            "Package name is required"
        });
      }


      const [
        result
      ] =
        await db.query(
          `
          INSERT INTO packages
          (
            name,
            description,
            price,
            status
          )
          VALUES (?, ?, ?, 'active')
          `,
          [
            name,
            description || null,
            Number(price) || 0
          ]
        );


      res.status(201).json({

        success: true,

        message:
          "Package created successfully",

        package_id:
          result.insertId

      });

    } catch (error) {

      console.error(
        "CREATE PACKAGE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to create package"
      });
    }
  }
);


/* =========================================================
   ADMIN — UPDATE PACKAGE
========================================================= */

app.put(
  "/api/admin/packages/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const packageId =
        Number(req.params.id);

      const {
        name,
        description,
        price,
        status
      } = req.body;


      if (!packageId) {

        return res.status(400).json({
          success: false,
          message:
            "Invalid package ID"
        });
      }


      await db.query(
        `
        UPDATE packages
        SET
          name=?,
          description=?,
          price=?,
          status=?
        WHERE id=?
        `,
        [
          name,
          description || null,
          Number(price) || 0,
          status || "active",
          packageId
        ]
      );


      res.json({

        success: true,

        message:
          "Package updated successfully"

      });

    } catch (error) {

      console.error(
        "UPDATE PACKAGE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to update package"
      });
    }
  }
);


/* =========================================================
   ADMIN — DELETE PACKAGE
========================================================= */

app.delete(
  "/api/admin/packages/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const packageId =
        Number(req.params.id);


      if (!packageId) {

        return res.status(400).json({
          success: false,
          message:
            "Invalid package ID"
        });
      }


      await db.query(
        `
        DELETE FROM packages
        WHERE id=?
        `,
        [packageId]
      );


      res.json({

        success: true,

        message:
          "Package deleted successfully"

      });

    } catch (error) {

      console.error(
        "DELETE PACKAGE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to delete package"
      });
    }
  }
);


/* =========================================================
   USER — PURCHASE PACKAGE
========================================================= */

app.post(
  "/api/packages/:id/purchase",
  authenticateToken,
  async (req, res) => {

    const connection =
      await db.getConnection();

    try {

      const packageId =
        Number(req.params.id);

      const userId =
        Number(req.user.id);


      await connection.beginTransaction();


      const [
        packageRows
      ] =
        await connection.query(
          `
          SELECT *
          FROM packages
          WHERE id=?
          AND status='active'
          LIMIT 1
          `,
          [packageId]
        );


      if (!packageRows.length) {

        await connection.rollback();
        connection.release();

        return res.status(404).json({
          success: false,
          message:
            "Package not found"
        });
      }


      const pkg =
        packageRows[0];


      const [
        result
      ] =
        await connection.query(
          `
          INSERT INTO user_packages
          (
            user_id,
            package_id,
            status,
            purchase_amount
          )
          VALUES (?, ?, 'pending', ?)
          `,
          [
            userId,
            packageId,
            pkg.price
          ]
        );


      await connection.query(
        `
        INSERT INTO admin_alerts
        (
          user_id,
          type,
          title,
          message,
          status
        )
        VALUES (?, ?, ?, ?, 'unread')
        `,
        [
          userId,
          "purchase_request",
          "Package Purchase Request",
          `A user submitted a purchase request for ${pkg.name}.`
        ]
      );


      await connection.commit();
      connection.release();


      res.status(201).json({

        success: true,

        message:
          "Package purchase request submitted",

        purchase_id:
          result.insertId

      });

    } catch (error) {

      try {
        await connection.rollback();
      } catch {}

      connection.release();


      console.error(
        "PURCHASE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to submit purchase request"
      });
    }
  }
);


/* =========================================================
   ADMIN — PURCHASE REQUESTS
========================================================= */

app.get(
  "/api/admin/purchase-requests",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const [
        rows
      ] =
        await db.query(
          `
          SELECT
            up.id,
            up.user_id,
            up.package_id,
            up.status,
            up.purchase_amount,
            up.created_at,

            u.name AS user_name,
            u.email AS user_email,

            p.name AS package_name

          FROM user_packages up

          LEFT JOIN users u
            ON up.user_id = u.id

          LEFT JOIN packages p
            ON up.package_id = p.id

          ORDER BY up.created_at DESC
          `
        );


      res.json({

        success: true,

        requests:
          rows

      });

    } catch (error) {

      console.error(
        "PURCHASE REQUESTS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to load purchase requests"
      });
    }
  }
);


/* =========================================================
   USER — TRANSACTIONS
========================================================= */

app.get(
  "/api/auth/transactions",
  authenticateToken,
  async (req, res) => {

    try {

      const [
        transactions
      ] =
        await db.query(
          `
          SELECT *
          FROM transactions
          WHERE user_id=?
          ORDER BY created_at DESC
          `,
          [req.user.id]
        );


      res.json({

        success: true,

        transactions

      });

    } catch (error) {

      console.error(
        "USER TRANSACTIONS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to load transactions"
      });
    }
  }
);


/* =========================================================
   USER — WALLET
========================================================= */

app.get(
  "/api/auth/wallet",
  authenticateToken,
  async (req, res) => {

    try {

      const [
        rows
      ] =
        await db.query(
          `
          SELECT
            id,
            wallet_balance,
            referral_code
          FROM users
          WHERE id=?
          `,
          [req.user.id]
        );


      if (!rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "User not found"
        });
      }


      res.json({

        success: true,

        wallet:
          rows[0]

      });

    } catch (error) {

      console.error(
        "WALLET ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to load wallet"
      });
    }
  }
);


/* =========================================================
   ADMIN — TREE
========================================================= */

app.get(
  "/api/admin/tree",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const [
        tree
      ] =
        await db.query(
          `
          SELECT
            bt.*,

            u.name,
            u.email,
            u.referral_code

          FROM binary_tree bt

          LEFT JOIN users u
            ON bt.user_id = u.id

          ORDER BY bt.id ASC
          `
        );


      res.json({

        success: true,

        tree

      });

    } catch (error) {

      console.error(
        "ADMIN TREE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to load tree"
      });
    }
  }
);


/* =========================================================
   ADMIN — DEPOSIT REQUESTS
========================================================= */

app.get(
  "/api/admin/deposit-requests",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const [
        rows
      ] =
        await db.query(
          `
          SELECT
            t.*,
            u.name AS user_name,
            u.email AS user_email

          FROM transactions t

          LEFT JOIN users u
            ON t.user_id = u.id

          WHERE t.type='deposit'

          ORDER BY t.created_at DESC
          `
        );


      res.json({

        success: true,

        requests:
          rows

      });

    } catch (error) {

      console.error(
        "DEPOSIT REQUESTS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to load deposit requests"
      });
    }
  }
);


/* =========================================================
   ADMIN — WITHDRAW REQUESTS
========================================================= */

app.get(
  "/api/admin/withdraw-requests",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    try {

      const [
        rows
      ] =
        await db.query(
          `
          SELECT
            t.*,
            u.name AS user_name,
            u.email AS user_email

          FROM transactions t

          LEFT JOIN users u
            ON t.user_id = u.id

          WHERE t.type='withdraw'

          ORDER BY t.created_at DESC
          `
        );


      res.json({

        success: true,

        requests:
          rows

      });

    } catch (error) {

      console.error(
        "WITHDRAW REQUESTS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to load withdraw requests"
      });
    }
  }
);


/* =========================================================
   ADMIN — TRANSACTION DECISION
========================================================= */

app.put(
  "/api/admin/transactions/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    const connection =
      await db.getConnection();

    try {

      const transactionId =
        Number(req.params.id);

      const action =
        String(
          req.body.action || ""
        )
          .trim()
          .toLowerCase();


      if (
        !transactionId ||
        ![
          "approve",
          "reject"
        ].includes(action)
      ) {

        connection.release();

        return res.status(400).json({
          success: false,
          message:
            "Invalid transaction or action"
        });
      }


      await connection.beginTransaction();


      const [
        rows
      ] =
        await connection.query(
          `
          SELECT *
          FROM transactions
          WHERE id=?
          FOR UPDATE
          `,
          [transactionId]
        );


      if (!rows.length) {

        await connection.rollback();
        connection.release();

        return res.status(404).json({
          success: false,
          message:
            "Transaction not found"
        });
      }


      const transaction =
        rows[0];


      if (
        transaction.status !==
        "pending"
      ) {

        await connection.rollback();
        connection.release();

        return res.status(400).json({
          success: false,
          message:
            "Transaction already processed"
        });
      }


      if (
        action === "approve" &&
        transaction.type ===
          "deposit"
      ) {

        await connection.query(
          `
          UPDATE users
          SET wallet_balance =
            wallet_balance + ?
          WHERE id=?
          `,
          [
            transaction.amount,
            transaction.user_id
          ]
        );
      }


      if (
        action === "approve" &&
        transaction.type ===
          "withdraw"
      ) {

        const [
          userRows
        ] =
          await connection.query(
            `
            SELECT wallet_balance
            FROM users
            WHERE id=?
            FOR UPDATE
            `,
            [transaction.user_id]
          );


        if (
          !userRows.length ||
          Number(
            userRows[0].wallet_balance
          ) <
          Number(transaction.amount)
        ) {

          await connection.rollback();
          connection.release();

          return res.status(400).json({
            success: false,
            message:
              "Insufficient wallet balance"
          });
        }


        await connection.query(
          `
          UPDATE users
          SET wallet_balance =
            wallet_balance - ?
          WHERE id=?
          `,
          [
            transaction.amount,
            transaction.user_id
          ]
        );
      }


      await connection.query(
        `
        UPDATE transactions
        SET status=?
        WHERE id=?
        `,
        [
          action === "approve"
            ? "approved"
            : "rejected",

          transactionId
        ]
      );


      await connection.commit();
      connection.release();


      res.json({

        success: true,

        message:
          `Transaction ${action}d successfully`

      });

    } catch (error) {

      try {
        await connection.rollback();
      } catch {}

      connection.release();


      console.error(
        "TRANSACTION DECISION ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to process transaction",
        error:
          error.message
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

      /*
        IMPORTANT:
        This endpoint should be removed or disabled
        after the first successful admin setup.
      */

      const email =
        "admin@proyjon.com";

      const password =
        "123456";


      const hashedPassword =
        await bcrypt.hash(
          password,
          10
        );


      const [
        rows
      ] =
        await db.query(
          `
          SELECT id
          FROM users
          WHERE email=?
          LIMIT 1
          `,
          [email]
        );


      if (rows.length) {

        await db.query(
          `
          UPDATE users
          SET
            password=?,
            role='admin'
          WHERE id=?
          `,
          [
            hashedPassword,
            rows[0].id
          ]
        );

      } else {

        const referralCode =
          await createUniqueReferralCode();


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
            "Administrator",
            email,
            hashedPassword,
            referralCode
          ]
        );
      }


      res.json({

        success: true,

        message:
          "Admin account is ready",

        email,
        password

      });

    } catch (error) {

      console.error(
        "SETUP ADMIN ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Failed to setup admin",
        error:
          error.message
      });
    }
  }
);


/* =========================================================
   404 API
========================================================= */

app.use(
  "/api",
  (req, res) => {

    res.status(404).json({

      success: false,

      message:
        "API endpoint not found",

      endpoint:
        req.method + " " + req.originalUrl

    });
  }
);


/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {

    console.error(
      "GLOBAL ERROR:",
      error
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

    await connectDatabase();

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
      "SERVER START ERROR:",
      error
    );

    process.exit(1);
  }
}


startServer();
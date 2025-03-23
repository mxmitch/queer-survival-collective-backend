require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.SECRET_KEY;

// ✅ Ensure required environment variables exist
if (!process.env.DB_USER || !SECRET_KEY) {
    console.error("❌ Missing environment variables!");
    process.exit(1);
}

// ✅ PostgreSQL connection (uses SSL)
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    ssl: {
        rejectUnauthorized: false
    }
});

// ✅ Middleware
app.use(express.json());
app.use(cookieParser());
app.use(helmet()); // Security headers

// ✅ CORS (Allow only frontend)
const allowedOrigins = ["http://localhost:3000"]; // Update for production
app.use(cors({
    origin: allowedOrigins,
    credentials: true
}));

// ✅ Rate Limit (Protects against brute force attacks)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Max 100 requests per IP
    message: "Too many requests, please try again later."
});
app.use(limiter);

// ✅ JWT Token Generation
const generateToken = (user) => {
    return jwt.sign({ id: user.user_id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
};

// ✅ Middleware to verify JWT Token
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Access denied. No token provided." });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ message: "Invalid or expired token." });
        req.user = decoded; // Attach user data to request
        next();
    });
};

// ✅ Root route
app.get("/", (req, res) => res.send("🚀 API is running!"));

// ✅ Register route (Hashes password before storing)
app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) return res.status(400).json({ message: "Username and password required." });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING user_id, username",
            [username, hashedPassword]
        );
        const token = generateToken(result.rows[0]);
        res.cookie("token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production" });
        res.status(201).json({ token });
    } catch (error) {
        console.error("❌ Registration Error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// ✅ Login route (Verifies password & generates token)
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) return res.status(400).json({ message: "Username and password required." });

    try {
        const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
        if (result.rows.length === 0) return res.status(400).json({ message: "Invalid username or password" });

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ message: "Invalid username or password" });

        const token = generateToken(user);
        res.cookie("token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production" });
        res.json({ token });
    } catch (error) {
        console.error("❌ Login Error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// ✅ Logout route (Clears cookie)
app.post("/logout", (req, res) => {
    res.clearCookie("token");
    res.json({ message: "Logged out successfully" });
});

// ✅ Protected route (Requires authentication)
app.get("/protected", verifyToken, (req, res) => {
    res.json({ message: "Access granted", user: req.user });
});

// ✅ Get all users (Protected)
app.get("/users", verifyToken, async (req, res) => {
    try {
        const result = await pool.query("SELECT user_id, username FROM users");
        res.json(result.rows);
    } catch (err) {
        console.error("❌ Error fetching users:", err);
        res.status(500).send("Server error");
    }
});

// ✅ Fetch columns for a board (Protected)
app.get("/api/columns/:board_id", verifyToken, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM columns WHERE board_id = $1", [req.params.board_id]);
        res.json(result.rows);
    } catch (err) {
        console.error("❌ Error fetching columns:", err);
        res.status(500).json({ error: "Failed to fetch columns" });
    }
});

// ✅ Fetch tasks for a column (Protected)
app.get("/api/tasks/:column_id", verifyToken, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM tasks WHERE column_id = $1", [req.params.column_id]);
        res.json(result.rows);
    } catch (err) {
        console.error("❌ Error fetching tasks:", err);
        res.status(500).json({ error: "Failed to fetch tasks" });
    }
});

// ✅ Add a new task (Requires authentication)
app.post("/api/tasks", verifyToken, async (req, res) => {
    const { column_id, task_title, description, priority, due_date } = req.body;
    try {
        const result = await pool.query(
            "INSERT INTO tasks (user_id, column_id, task_title, description, priority, due_date) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
            [req.user.id, column_id, task_title, description, priority, due_date]
        );
        res.json(result.rows[0]);
    } catch (err) {
        console.error("❌ Task creation error:", err);
        res.status(500).json({ error: "Failed to create task" });
    }
});

// ✅ Fetch all boards (Protected)
app.get('/api/boards', async (req, res) => {
  try {
      const result = await pool.query(`
          SELECT 
              b.board_id, 
              b.board_name, 
              COALESCE(json_agg(
                  json_build_object(
                      'column_id', c.column_id, 
                      'column_name', c.column_name, 
                      'position', c.position
                  )
              ) FILTER (WHERE c.column_id IS NOT NULL), '[]') AS columns
          FROM boards b
          LEFT JOIN columns c ON b.board_id = c.board_id
          GROUP BY b.board_id
          ORDER BY b.board_id;
      `);

      res.json(result.rows);
  } catch (err) {
      console.error('Error fetching boards:', err);
      res.status(500).json({ error: 'Failed to fetch boards' });
  }
});

// ✅ Add a column (Protected)
app.post("/api/columns", verifyToken, async (req, res) => {
    const { board_id, column_name, position } = req.body;
    try {
        const result = await pool.query(
            "INSERT INTO columns (board_id, column_name, position) VALUES ($1, $2, $3) RETURNING *",
            [board_id, column_name, position]
        );
        res.json(result.rows[0]);
    } catch (err) {
        console.error("❌ Error creating column:", err);
        res.status(500).json({ error: "Failed to create column" });
    }
});

// ✅ Start the server
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));

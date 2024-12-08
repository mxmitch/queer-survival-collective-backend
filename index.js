require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;


// PostgreSQL connection
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

const SECRET_KEY = process.env.SECRET_KEY;

// Middleware
app.use(express.json());
app.use(cors());

const generateToken = (user) => {
    return jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
  };


// Root route
app.get("/", (req, res) => {
    res.send("Welcome to the API! The server is running.");
});

// Example API route
app.get("/users", async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM users");
        res.json(result.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

app.get('/api/boards', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM boards');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch boards' });
    }
});

// Fetch columns for a specific board
app.get('/api/columns/:board_id', async (req, res) => {
    const boardId = req.params.board_id;
    try {
        const result = await pool.query('SELECT * FROM columns WHERE board_id = $1', [boardId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch columns' });
    }
});

// Fetch tasks for a specific column
app.get('/api/tasks/:column_id', async (req, res) => {
    const columnId = req.params.column_id;
    try {
        const result = await pool.query('SELECT * FROM tasks WHERE column_id = $1', [columnId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    }
});

// Add a new task
app.post('/api/tasks', async (req, res) => {
    const { user_id, column_id, task_title, description, priority, due_date } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO tasks (user_id, column_id, task_title, description, priority, due_date) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [user_id, column_id, task_title, description, priority, due_date]
        );
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create task' });
    }
});

// Register route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }
  
    try {
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Insert user into the database
      const result = await pool.query(
        'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING user_id, username',
        [username, hashedPassword]
      );
  
      const user = result.rows[0];
  
      // Generate JWT token
      const token = generateToken(user);
  
      res.status(201).json({ token });
    } catch (error) {
      console.error('Error registering user:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  
  // Login route
  app.post('/login', async (req, res) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }
  
    try {
      // Find user in the database
      const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  
      if (result.rows.length === 0) {
        return res.status(400).json({ message: 'Invalid username or password' });
      }
  
      const user = result.rows[0];
  
      // Compare the hashed password with the one provided
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.status(400).json({ message: 'Invalid username or password' });
      }
  
      // Generate JWT token
      const token = generateToken(user);
  
      res.json({ token });
    } catch (error) {
      console.error('Error logging in:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  
  // A protected route to verify JWT token
  app.get('/protected', (req, res) => {
    const token = req.headers['authorization'];
  
    if (!token) {
      return res.status(403).json({ message: 'Token is required' });
    }
  
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid or expired token' });
      }
  
      res.json({ message: 'Access granted', user: decoded });
    });
  });

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});


const express = require('express');
const pool = require('./db');
const cors = require('cors');

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json()); // Parse JSON bodies

// Test route to get data
app.get('/api/data', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM your_table_name');
    res.json(result.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

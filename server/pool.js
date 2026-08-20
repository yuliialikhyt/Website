const { Pool } = require("pg");

// Reads connection info from DATABASE_URL, e.g.:
// postgres://user:password@localhost:5432/martel
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Uncomment if your Postgres host requires SSL (most managed hosts do)
    // ssl: { rejectUnauthorized: false },
});

module.exports = pool;
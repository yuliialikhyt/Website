const { Pool } = require("pg");

// Reads connection info from DATABASE_URL, e.g. (Supabase transaction pooler):
// postgres://postgres.your-project-ref:[YOUR-PASSWORD]@aws-0-region.pooler.supabase.com:6543/postgres
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Supabase (and most managed Postgres hosts) require SSL.
    // rejectUnauthorized: false is standard here since Supabase's certs
    // aren't in Node's default trust store.
    ssl: { rejectUnauthorized: false },
});

module.exports = pool;
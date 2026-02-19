import pg from "pg";
import dotenv from "dotenv";

dotenv.config();

const {
  PGHOST = process.env.DB_HOST || "localhost",
  PGPORT = process.env.DB_PORT,
  PGUSER = process.env.DB_USER,
  PGPASSWORD = process.env.DB_PASSWORD,
  PGDATABASE = process.env.DB_DATABASE,
  DATABASE_URL = process.env.DATABASE_URL,
  PGSSLMODE,
  PGSSL
} = process.env;

const pool = (() => {
  if (DATABASE_URL) {
    const isSupabase = DATABASE_URL.includes("supabase.co");
    const needSSL =
      isSupabase ||
      String(PGSSL || PGSSLMODE || "").toLowerCase() === "require" ||
      String(PGSSL || "").toLowerCase() === "true";
    return new pg.Pool({
      connectionString: DATABASE_URL,
      ssl: needSSL ? { rejectUnauthorized: false } : false
    });
  }
  if (!PGHOST || !PGUSER || !PGDATABASE) {
    console.warn(
      "PostgreSQL env vars missing: set PGHOST, PGUSER, PGPASSWORD (if required), PGDATABASE or DATABASE_URL"
    );
  }
  const needSSL =
    String(PGSSL || PGSSLMODE || "").toLowerCase() === "require" ||
    String(PGSSL || "").toLowerCase() === "true";
  const cfg = {
    host: PGHOST,
    port: Number(PGPORT),
    user: PGUSER,
    database: PGDATABASE,
    ssl: needSSL ? { rejectUnauthorized: false } : false
  };
  if (PGPASSWORD !== undefined && PGPASSWORD !== null) {
    cfg.password = String(PGPASSWORD);
  }
  return new pg.Pool(cfg);
})();

export async function query(text, params) {
  const client = await pool.connect();
  try {
    const res = await client.query(text, params);
    return res;
  } finally {
    client.release();
  }
}

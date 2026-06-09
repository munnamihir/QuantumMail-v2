import pg from "pg";
const { Pool } = pg;

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error("DATABASE_URL is required.");

const isProduction = process.env.NODE_ENV === "production";

export const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: isProduction
    ? { rejectUnauthorized: false }
    : false
});

pool.on("error", (err) => console.error("Postgres pool error:", err));

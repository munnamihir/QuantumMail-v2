import pg from "pg";
const { Pool } = pg;

export class PostgresStore {
  constructor() {
    const url = process.env.DATABASE_URL;
    if (!url) throw new Error("DATABASE_URL is required for PostgresStore.");

    this.pool = new Pool({
      connectionString: url,
      // Render Postgres typically requires SSL in many environments.
      // If your Render DB is in the same Render region/private network, SSL may not be required.
      // This setting is safe for most hosted PG providers.
      ssl: { rejectUnauthorized: false }
    });
  }

  async init() {
    // Ensure table exists (you can also rely purely on migrations if you prefer).
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS qm_org_state (
        org_id TEXT PRIMARY KEY,
        state  JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
  }

  async loadOrgState(orgId) {
    const { rows } = await this.pool.query(
      `SELECT state FROM qm_org_state WHERE org_id = $1`,
      [orgId]
    );
    if (!rows.length) return null;
    return rows[0].state;
  }

  async saveOrgState(orgId, state) {
    await this.pool.query(
      `
      INSERT INTO qm_org_state (org_id, state, updated_at)
      VALUES ($1, $2::jsonb, NOW())
      ON CONFLICT (org_id)
      DO UPDATE SET state = EXCLUDED.state, updated_at = NOW()
      `,
      [orgId, JSON.stringify(state)]
    );
  }

  async loadAllOrgs() {
    const { rows } = await this.pool.query(`SELECT org_id, state FROM qm_org_state`);
    const orgs = {};
    for (const r of rows) orgs[r.org_id] = r.state;
    return orgs;
  }
}

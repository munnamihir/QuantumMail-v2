// server/orgStore.js
import { pool } from "./db.js";

/**
 * qm_org_store schema expectation:
 *   org_id      TEXT PRIMARY KEY
 *   data        JSONB NOT NULL DEFAULT '{}'::jsonb
 *   updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
 *   company_id  TEXT NULL        -- optional but recommended (snake_case)
 *
 * IMPORTANT:
 * - There is NO physical org_name column.
 * - orgName lives inside data JSON: data->>'orgName'
 */

export async function peekOrg(orgId) {
  const id = String(orgId || "").trim();
  if (!id) return null;

  const { rows } = await pool.query(
    `
    select
      org_id,
      data,
      updated_at,
      company_id
    from qm_org_store
    where org_id = $1
    limit 1
    `,
    [id]
  );

  return rows[0] || null;
}

export async function getOrg(orgId) {
  const rec = await peekOrg(orgId);
  if (!rec) return null;

  // normalize to a single object shape used across server
  return {
    orgId: rec.org_id,
    data: rec.data || {},
    updatedAt: rec.updated_at,
    companyId: rec.company_id || rec?.data?.companyId || null
  };
}

/**
 * Save org JSON (and optionally companyId as a real column).
 * This does an UPSERT so it works for new + existing orgs.
 */
export async function saveOrg(orgId, data, { companyId = null } = {}) {
  const id = String(orgId || "").trim();
  if (!id) throw new Error("saveOrg: orgId required");

  const obj = data && typeof data === "object" ? data : {};

  // Prefer storing companyId in a real column if you have it,
  // but keep it in JSON too so older code keeps working.
  const cid = (companyId ?? obj.companyId ?? null);
  if (cid && !obj.companyId) obj.companyId = cid;

  // If your table uses camelCase quoted column "companyId"
  // replace company_id with "companyId" in BOTH places below.
  const { rows } = await pool.query(
    `
    insert into qm_org_store (org_id, data, company_id, updated_at)
    values ($1, $2::jsonb, $3, now())
    on conflict (org_id)
    do update set
      data = excluded.data,
      company_id = excluded.company_id,
      updated_at = now()
    returning org_id, data, updated_at, company_id
    `,
    [id, JSON.stringify(obj), cid]
  );

  const rec = rows[0];
  return {
    orgId: rec.org_id,
    data: rec.data || {},
    updatedAt: rec.updated_at,
    companyId: rec.company_id || rec?.data?.companyId || null
  };
}

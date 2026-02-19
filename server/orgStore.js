import { pool } from "./db.js";

function defaultPolicies() {
  return {
    forceAttachmentEncryption: false,
    disablePassphraseMode: false,
    enforceKeyRotationDays: 0,
    requireReauthForDecrypt: true,
  };
}

function ensureOrgShape(org) {
  if (!org) org = {};
  if (!org.users) org.users = [];
  if (!org.audit) org.audit = [];
  if (!org.messages) org.messages = {};
  if (!org.invites) org.invites = {};
  if (!org.policies) org.policies = defaultPolicies();
  if (!org.keyring) org.keyring = null;
  return org;
}

export async function peekOrg(orgId) {
  const oid = String(orgId || "").trim();
  if (!oid) return null;

  const { rows } = await pool.query(
    "select data from qm_org_store where org_id = $1",
    [oid]
  );
  if (!rows.length) return null;

  return ensureOrgShape(rows[0].data);
}

export async function getOrg(orgId) {
  const oid = String(orgId || "").trim();
  if (!oid) return null;

  const existing = await peekOrg(oid);
  if (existing) return existing;

  const fresh = ensureOrgShape({
    users: [],
    audit: [],
    messages: {},
    invites: {},
    policies: defaultPolicies(),
    keyring: null,
  });

  await pool.query(
    `insert into qm_org_store (org_id, data)
     values ($1, $2::jsonb)
     on conflict (org_id) do nothing`,
    [oid, JSON.stringify(fresh)]
  );

  return (await peekOrg(oid)) || fresh;
}

export async function saveOrg(orgId, org) {
  const oid = String(orgId || "").trim();
  if (!oid) throw new Error("saveOrg requires orgId");

  const normalized = ensureOrgShape(org);

  await pool.query(
    `insert into qm_org_store (org_id, data, updated_at)
     values ($1, $2::jsonb, now())
     on conflict (org_id)
     do update set data = excluded.data, updated_at = now()`,
    [oid, JSON.stringify(normalized)]
  );

  return true;
}

import dotenv from "dotenv";

import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import { query } from "./db.js";
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// Serve static files from frontend dist/ in production
const frontendDistDir = path.join(__dirname, "..", "frontend", "dist");
const isDist = fs.existsSync(frontendDistDir);

if (isDist) {
  app.use(express.static(frontendDistDir));
}

app.get("/api/employees", async (req, res) => {
  try {
    const { rows } = await query(
      `SELECT id, name, department, currentsalary, grade, increment, incrementedsalary
       FROM public.employeedetails
       ORDER BY id`
    );
    res.json(rows);
  } catch (err) {
    console.error("DB query failed", err.message);
    res.status(500).json({
      error: "Database connection/query failed. Verify PostgreSQL env vars and table exist."
    });
  }
});

app.get("/api/employees/:id/inputdetails", async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await query(
      `SELECT id, name, department, currentsalary, kpiscore, attendance, behavioralrating, managerrating
       FROM employeeinputdetails
       WHERE id = $1`,
      [id]
    );
    if (!rows.length) return res.status(404).json({ error: "Employee input details not found" });
    res.json(rows[0]);
  } catch (err) {
    console.error("DB query failed", err.message);
    res.status(500).json({ error: `Failed to fetch employee input details: ${err.message}` });
  }
});

app.get("/api/weights", async (_req, res) => {
  try {
    const { rows } = await query(
      `SELECT metric, weightpercentage
       FROM weightdetails
       ORDER BY metric`
    );
    res.json(rows);
  } catch (err) {
    console.error("DB query failed", err.message);
    res.status(500).json({ error: `Failed to fetch weights: ${err.message}` });
  }
});

app.get("/api/invalid", async (_req, res) => {
  try {
    const { rows } = await query(
      `SELECT id, name, department, currentsalary, kpiscore, attendance, behavioralrating, managerrating
       FROM invaliddata
       ORDER BY id`
    );
    res.json(rows);
  } catch (err) {
    console.error("DB query failed", err.message);
    res.status(500).json({ error: `Failed to fetch invalid data: ${err.message}` });
  }
});

app.post("/api/employeedetails", async (req, res) => {
  try {
    const { actor, id, name, department, currentsalary, grade, increment, incrementedsalary } = req.body || {};
    if (!actor) return res.status(401).json({ error: "Actor required" });
    const allowed = await hasPermission(actor, "add");
    if (!allowed) return res.status(403).json({ error: "Not authorized" });
    if (!name || !department) return res.status(400).json({ error: "Name and department required" });
    const cols = ["name","department","currentsalary","grade","increment","incrementedsalary"];
    const vals = [name, department, currentsalary ?? null, grade ?? null, increment ?? null, incrementedsalary ?? null];
    if (id !== undefined && id !== null && String(id).trim() !== "") {
      cols.unshift("id");
      vals.unshift(id);
    }
    const placeholders = vals.map((_, i) => `$${i + 1}`).join(", ");
    const sql = `INSERT INTO public.employeedetails (${cols.join(",")}) VALUES (${placeholders}) RETURNING id`;
    const params = vals;
    const { rows } = await query(sql, params);
    res.status(201).json({ id: rows[0].id });
  } catch (err) {
    console.error("Add employeedetails failed", err.message);
    res.status(500).json({ error: `Add employeedetails error: ${err.message}` });
  }
});

app.put("/api/employeedetails/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { actor, name, department, currentsalary, grade, increment, incrementedsalary } = req.body || {};
    if (!actor) return res.status(401).json({ error: "Actor required" });
    const allowed = await hasPermission(actor, "update");
    if (!allowed) return res.status(403).json({ error: "Not authorized" });
    const fields = [
      ["name", name],
      ["department", department],
      ["currentsalary", currentsalary],
      ["grade", grade],
      ["increment", increment],
      ["incrementedsalary", incrementedsalary]
    ].filter(([_, v]) => v !== undefined);
    if (!fields.length) return res.status(400).json({ error: "No fields to update" });
    const setSql = fields.map((f, i) => `${f[0]} = $${i + 1}`).join(", ");
    const sql = `UPDATE public.employeedetails SET ${setSql} WHERE id = $${fields.length + 1} RETURNING id`;
    const params = [...fields.map(f => f[1]), id];
    const { rows } = await query(sql, params);
    if (!rows.length) return res.status(404).json({ error: "Employee not found" });
    res.json({ id: rows[0].id });
  } catch (err) {
    console.error("Update employeedetails failed", err.message);
    res.status(500).json({ error: `Update employeedetails error: ${err.message}` });
  }
});

app.delete("/api/employeedetails/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { actor } = req.body || {};
    if (!actor) return res.status(401).json({ error: "Actor required" });
    const allowed = await hasPermission(actor, "delete");
    if (!allowed) return res.status(403).json({ error: "Not authorized" });
    const { rows } = await query(`DELETE FROM public.employeedetails WHERE id = $1 RETURNING id`, [id]);
    if (!rows.length) return res.status(404).json({ error: "Employee not found" });
    res.json({ id: rows[0].id });
  } catch (err) {
    console.error("Delete employeedetails failed", err.message);
    res.status(500).json({ error: `Delete employeedetails error: ${err.message}` });
  }
});

app.post("/api/invaliddata", async (req, res) => {
  try {
    const { actor, id, name, department, currentsalary, kpiscore, attendance, behavioralrating, managerrating } = req.body || {};
    if (!actor) return res.status(401).json({ error: "Actor required" });
    const allowed = await hasPermission(actor, "add");
    if (!allowed) return res.status(403).json({ error: "Not authorized" });
    if (!name || !department) return res.status(400).json({ error: "Name and department required" });
    const cols = ["name","department","currentsalary","kpiscore","attendance","behavioralrating","managerrating"];
    const vals = [name, department, currentsalary ?? null, kpiscore ?? null, attendance ?? null, behavioralrating ?? null, managerrating ?? null];
    if (id !== undefined && id !== null && String(id).trim() !== "") {
      cols.unshift("id");
      vals.unshift(id);
    }
    const placeholders = vals.map((_, i) => `$${i + 1}`).join(", ");
    const sql = `INSERT INTO public.invaliddata (${cols.join(",")}) VALUES (${placeholders}) RETURNING id`;
    const params = vals;
    const { rows } = await query(sql, params);
    res.status(201).json({ id: rows[0].id });
  } catch (err) {
    console.error("Add invaliddata failed", err.message);
    res.status(500).json({ error: `Add invaliddata error: ${err.message}` });
  }
});

app.put("/api/invaliddata/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { actor, name, department, currentsalary, kpiscore, attendance, behavioralrating, managerrating } = req.body || {};
    if (!actor) return res.status(401).json({ error: "Actor required" });
    const allowed = await hasPermission(actor, "update");
    if (!allowed) return res.status(403).json({ error: "Not authorized" });
    const fields = [
      ["name", name],
      ["department", department],
      ["currentsalary", currentsalary],
      ["kpiscore", kpiscore],
      ["attendance", attendance],
      ["behavioralrating", behavioralrating],
      ["managerrating", managerrating]
    ].filter(([_, v]) => v !== undefined);
    if (!fields.length) return res.status(400).json({ error: "No fields to update" });
    const setSql = fields.map((f, i) => `${f[0]} = $${i + 1}`).join(", ");
    const sql = `UPDATE public.invaliddata SET ${setSql} WHERE id = $${fields.length + 1} RETURNING id`;
    const params = [...fields.map(f => f[1]), id];
    const { rows } = await query(sql, params);
    if (!rows.length) return res.status(404).json({ error: "Invalid row not found" });
    res.json({ id: rows[0].id });
  } catch (err) {
    console.error("Update invaliddata failed", err.message);
    res.status(500).json({ error: `Update invaliddata error: ${err.message}` });
  }
});

app.delete("/api/invaliddata/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { actor } = req.body || {};
    if (!actor) return res.status(401).json({ error: "Actor required" });
    const allowed = await hasPermission(actor, "delete");
    if (!allowed) return res.status(403).json({ error: "Not authorized" });
    const { rows } = await query(`DELETE FROM public.invaliddata WHERE id = $1 RETURNING id`, [id]);
    if (!rows.length) return res.status(404).json({ error: "Invalid row not found" });
    res.json({ id: rows[0].id });
  } catch (err) {
    console.error("Delete invaliddata failed", err.message);
    res.status(500).json({ error: `Delete invaliddata error: ${err.message}` });
  }
});

app.get("/api/permissions/:username", async (req, res) => {
  try {
    const { username } = req.params;
    if (!username) return res.status(400).json({ error: "Username required" });
    const perms = await getPermissions(username);
    res.json(perms);
  } catch (err) {
    res.status(500).json({ error: `Permissions error: ${err.message}` });
  }
});

app.post("/api/set_permissions", async (req, res) => {
  try {
    const { actor, username, can_add, can_update, can_delete } = req.body || {};
    if (!actor) return res.status(401).json({ error: "Actor required" });
    const role = await getUserRole(actor);
    if (role !== "admin") return res.status(403).json({ error: "Not authorized" });
    if (!username) return res.status(400).json({ error: "Username required" });
    await setPermissions(username, { can_add, can_update, can_delete });
    res.json({ status: "ok" });
  } catch (err) {
    res.status(500).json({ error: `Set permissions error: ${err.message}` });
  }
});

async function getHrLoginMeta() {
  const t = await query(
    `SELECT table_schema, table_name
     FROM information_schema.tables
     WHERE lower(table_name) = 'hrlogin'
     ORDER BY CASE WHEN table_schema = 'public' THEN 0 ELSE 1 END, table_name
     LIMIT 1`
  );
  const table = t.rows[0];
  const fq = table ? `"${table.table_schema}"."${table.table_name}"` : null;
  const colsRes = await query(
    `SELECT column_name
     FROM information_schema.columns
     WHERE lower(table_name) = 'hrlogin'
       AND table_schema = $1
     ORDER BY ordinal_position`,
    [table ? table.table_schema : 'public']
  );
  const rawCols = colsRes.rows.map(r => String(r.column_name));
  const colsLower = rawCols.map(c => c.toLowerCase());
  const idCandidates = ["username","email","user","login","userid"];
  const pwCandidates = ["password","passwd","pass","pwd"];
  const roleCandidates = ["role","roles","userrole","is_admin"];
  const permCandidates = ["permissions","permisions","perms","perm"];
  const emailCandidates = ["email","mail"];
  const identityIdx = idCandidates.map(c => colsLower.indexOf(c)).find(i => i >= 0);
  const passwordIdx = pwCandidates.map(c => colsLower.indexOf(c)).find(i => i >= 0);
  const roleIdx = roleCandidates.map(c => colsLower.indexOf(c)).find(i => i >= 0);
  const permIdx = permCandidates.map(c => colsLower.indexOf(c)).find(i => i >= 0);
  const emailIdx = emailCandidates.map(c => colsLower.indexOf(c)).find(i => i >= 0);
  const identityCol = identityIdx >= 0 ? rawCols[identityIdx] : null;
  const passwordCol = passwordIdx >= 0 ? rawCols[passwordIdx] : null;
  const roleCol = roleIdx >= 0 ? rawCols[roleIdx] : null;
  const permCol = permIdx >= 0 ? rawCols[permIdx] : null;
  const emailCol = emailIdx >= 0 ? rawCols[emailIdx] : null;
  const idQuoted = identityCol ? `"${identityCol}"` : null;
  const pwQuoted = passwordCol ? `"${passwordCol}"` : null;
  const roleQuoted = roleCol ? `"${roleCol}"` : null;
  const permQuoted = permCol ? `"${permCol}"` : null;
  const emailQuoted = emailCol ? `"${emailCol}"` : null;
  return { tableFq: fq, identityCol: idQuoted, passwordCol: pwQuoted, roleCol: roleQuoted, permCol: permQuoted, emailCol: emailQuoted };
}

async function ensureRolesTable() {
  await query(`CREATE TABLE IF NOT EXISTS public.userroles (
    username text PRIMARY KEY,
    role text NOT NULL CHECK (role IN ('admin','hr'))
  )`);
}

async function ensurePermissionsTable() {
  await query(`CREATE TABLE IF NOT EXISTS public.userpermissions (
    username text PRIMARY KEY,
    can_add boolean DEFAULT false,
    can_update boolean DEFAULT false,
    can_delete boolean DEFAULT false
  )`);
}

async function ensureBusinessTables() {
  await query(`CREATE TABLE IF NOT EXISTS public.employeedetails (
    id varchar(8) PRIMARY KEY,
    name varchar(30) NOT NULL,
    department varchar(20) NOT NULL,
    currentsalary numeric(15,2),
    grade char(1),
    increment numeric(2,0),
    incrementedsalary numeric(15,2)
  )`);
  await query(`CREATE TABLE IF NOT EXISTS public.employeeinputdetails (
    id varchar(8) PRIMARY KEY,
    name varchar(100),
    department varchar(100),
    currentsalary numeric(15,2),
    kpiscore integer,
    attendance integer,
    behavioralrating integer,
    managerrating integer
  )`);
  await query(`CREATE TABLE IF NOT EXISTS public.invaliddata (
    id varchar(100),
    name varchar(100),
    department varchar(100),
    currentsalary varchar(100),
    kpiscore varchar(100),
    attendance varchar(100),
    behavioralrating varchar(100),
    managerrating varchar(100)
  )`);
  await query(`CREATE TABLE IF NOT EXISTS public.weightdetails (
    metric varchar(100) PRIMARY KEY,
    weightpercentage integer NOT NULL
  )`);
}

function parsePerms(raw) {
  if (raw === null || raw === undefined) return { can_add: false, can_update: false, can_delete: false };
  if (typeof raw === "boolean") return { can_add: raw, can_update: raw, can_delete: raw };
  try {
    const s = String(raw).trim();
    if (!s) return { can_add: false, can_update: false, can_delete: false };
    if (s === "true" || s === "1" || s === "yes" || s === "y") return { can_add: true, can_update: true, can_delete: true };
    if (s.startsWith("{") || s.startsWith("[")) {
      const obj = JSON.parse(s);
      if (Array.isArray(obj)) {
        const set = new Set(obj.map(v => String(v).toLowerCase()));
        return {
          can_add: set.has("add"),
          can_update: set.has("update"),
          can_delete: set.has("delete")
        };
      }
      return {
        can_add: !!obj.can_add,
        can_update: !!obj.can_update,
        can_delete: !!obj.can_delete
      };
    }
    const parts = s.split(/[,\s]+/).map(x => x.toLowerCase());
    const set = new Set(parts);
    return {
      can_add: set.has("add") || set.has("create") || set.has("insert"),
      can_update: set.has("update") || set.has("edit"),
      can_delete: set.has("delete") || set.has("remove")
    };
  } catch {
    return { can_add: false, can_update: false, can_delete: false };
  }
}

async function getPermissions(username) {
  const { tableFq, identityCol, permCol } = await getHrLoginMeta();
  if (tableFq && identityCol && permCol) {
    const sql = `SELECT ${permCol} AS permissions FROM ${tableFq} WHERE lower(${identityCol}) = lower($1) LIMIT 1`;
    const { rows } = await query(sql, [username]);
    if (rows.length) return parsePerms(rows[0].permissions);
  }
  await ensurePermissionsTable();
  const { rows } = await query(
    `SELECT can_add, can_update, can_delete FROM public.userpermissions WHERE lower(username) = lower($1)`,
    [username]
  );
  if (!rows.length) return { can_add: false, can_update: false, can_delete: false };
  const r = rows[0];
  return {
    can_add: Boolean(r.can_add),
    can_update: Boolean(r.can_update),
    can_delete: Boolean(r.can_delete)
  };
}

async function setPermissions(username, perms) {
  const { tableFq, identityCol, permCol } = await getHrLoginMeta();
  if (tableFq && identityCol && permCol) {
    const list = [
      perms.can_add ? "add" : null,
      perms.can_update ? "update" : null,
      perms.can_delete ? "delete" : null
    ].filter(Boolean);
    const val = list.join(",");
    const sql = `UPDATE ${tableFq} SET ${permCol} = $1 WHERE lower(${identityCol}) = lower($2)`;
    await query(sql, [val, username]);
    return;
  }
  await ensurePermissionsTable();
  await query(
    `INSERT INTO public.userpermissions (username, can_add, can_update, can_delete)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (username) DO UPDATE SET
       can_add = EXCLUDED.can_add,
       can_update = EXCLUDED.can_update,
       can_delete = EXCLUDED.can_delete`,
    [username, Boolean(perms.can_add), Boolean(perms.can_update), Boolean(perms.can_delete)]
  );
}

async function hasPermission(username, action) {
  const role = await getUserRole(username);
  if (role === "admin") return true;
  const perms = await getPermissions(username);
  if (action === "add") return perms.can_add;
  if (action === "update") return perms.can_update;
  if (action === "delete") return perms.can_delete;
  return false;
}

async function getUserRole(username) {
  const { tableFq, identityCol, roleCol } = await getHrLoginMeta();
  if (tableFq && identityCol && roleCol) {
    const sql = `SELECT ${roleCol} AS role FROM ${tableFq} WHERE lower(${identityCol}) = lower($1) LIMIT 1`;
    const { rows } = await query(sql, [username]);
    if (rows.length && rows[0].role) {
      const raw = rows[0].role;
      if (typeof raw === "boolean") return raw ? "admin" : "hr";
      const r = String(raw).trim().toLowerCase();
      if (["admin","administrator","superuser","true","1","yes","y"].includes(r)) return "admin";
      return "hr";
    }
  }
  const { rows } = await query(`SELECT role FROM public.userroles WHERE lower(username) = lower($1)`, [username]);
  if (rows.length) {
    const r = String(rows[0].role).trim().toLowerCase();
    if (["admin","administrator","superuser"].includes(r)) return "admin";
    return "hr";
  }
  return "hr";
}

async function setUserRole(username, role) {
  const { tableFq, identityCol, roleCol } = await getHrLoginMeta();
  if (tableFq && identityCol && roleCol) {
    const sql = `UPDATE ${tableFq} SET ${roleCol} = $1 WHERE lower(${identityCol}) = lower($2)`;
    await query(sql, [role, username]);
    return;
  }
  await query(
    `INSERT INTO public.userroles (username, role) VALUES ($1, $2)
     ON CONFLICT (username) DO UPDATE SET role = EXCLUDED.role`,
    [username, role]
  );
}

app.get("/api/whoami", async (req, res) => {
  try {
    const username = (req.headers["x-user"] || req.query.username || "").toString();
    if (!username) return res.status(400).json({ error: "Username required" });
    await ensureRolesTable();
    const role = await getUserRole(username);
    res.json({ username, role });
  } catch (err) {
    res.status(500).json({ error: `whoami error: ${err.message}` });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, email, password } = req.body || {};
    const identity = username ?? email;
    if (!identity || !password) return res.status(400).json({ error: "Username and password required" });
    const { tableFq, identityCol, passwordCol } = await getHrLoginMeta();
    if (!tableFq || !identityCol || !passwordCol) return res.status(500).json({ error: "hrlogin table missing expected columns" });
    const sql = `SELECT ${identityCol} AS identity, ${passwordCol} AS password FROM ${tableFq} WHERE lower(${identityCol}) = lower($1) LIMIT 1`;
    const { rows } = await query(sql, [identity]);
    if (!rows.length) return res.status(401).json({ error: "Invalid credentials" });
    const ok = String(rows[0].password) === String(password);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });
    await ensureRolesTable();
    res.json({ status: "ok", user: { username: identity } });
  } catch (err) {
    console.error("Login failed", err.message);
    res.status(500).json({ error: `Login error: ${err.message}` });
  }
});

app.post("/api/forgot", async (req, res) => {
  try {
    const { username } = req.body || {};
    if (!username) return res.status(400).json({ error: "Username required" });
    const { tableFq, identityCol, passwordCol } = await getHrLoginMeta();
    if (!tableFq || !identityCol || !passwordCol) return res.status(500).json({ error: "hrlogin table missing expected columns" });
    const checkSql = `SELECT 1 FROM ${tableFq} WHERE lower(${identityCol}) = lower($1)`;
    const { rows } = await query(checkSql, [username]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    const updSql = `UPDATE ${tableFq} SET ${passwordCol} = $1 WHERE lower(${identityCol}) = lower($2)`;
    await query(updSql, ["password123", username]);
    res.json({ status: "ok", message: "Password reset to password123" });
  } catch (err) {
    console.error("Forgot password failed", err.message);
    res.status(500).json({ error: `Reset error: ${err.message}` });
  }
});

app.post("/api/change_password", async (req, res) => {
  try {
    const { username, current, next } = req.body || {};
    if (!username || !current || !next) {
      return res.status(400).json({ error: "Username, current and new password required" });
    }
    const { tableFq, identityCol, passwordCol } = await getHrLoginMeta();
    if (!tableFq || !identityCol || !passwordCol) return res.status(500).json({ error: "hrlogin table missing expected columns" });
    const selSql = `SELECT ${passwordCol} AS password FROM ${tableFq} WHERE lower(${identityCol}) = lower($1) LIMIT 1`;
    const { rows } = await query(selSql, [username]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    if (String(rows[0].password) !== String(current)) {
      return res.status(401).json({ error: "Current password incorrect" });
    }
    const updSql = `UPDATE ${tableFq} SET ${passwordCol} = $1 WHERE lower(${identityCol}) = lower($2)`;
    await query(updSql, [next, username]);
    res.json({ status: "ok", message: "Password updated" });
  } catch (err) {
    console.error("Change password failed", err.message);
    res.status(500).json({ error: `Change password error: ${err.message}` });
  }
});

app.post("/api/add_user", async (req, res) => {
  try {
    const { actor, username, email, password, role } = req.body || {};
    if (!actor) return res.status(401).json({ error: "Actor required" });
    const actorRole = await getUserRole(actor);
    if (actorRole !== "admin") return res.status(403).json({ error: "Not authorized" });
    if ((!username && !email) || !password) return res.status(400).json({ error: "Username/email and password required" });
    const { tableFq, identityCol, passwordCol, roleCol, emailCol } = await getHrLoginMeta();
    if (!tableFq || !identityCol || !passwordCol) return res.status(500).json({ error: "hrlogin table missing expected columns" });
    // Always provide both username and email if both columns exist
    let identity = username ?? email;
    let emailVal = email ?? username;
    // If identityCol and emailCol are the same, just use one value
    const stripName = s => String(s || "").replace(/"/g, "").toLowerCase();
    const sameCol = emailCol && stripName(identityCol) === stripName(emailCol);
    const existsSql = `SELECT 1 FROM ${tableFq} WHERE lower(${identityCol}) = lower($1)`;
    const exists = await query(existsSql, [identity]);
    if (exists.rows.length) return res.status(409).json({ error: "User already exists" });
    let cols = [identityCol, passwordCol];
    let vals = [identity, password];
    if (emailCol) {
      if (!sameCol) {
        cols.push(emailCol);
        vals.push(emailVal);
      }
    }
    const placeholders = vals.map((_, i) => `$${i + 1}`).join(", ");
    const insSql = `INSERT INTO ${tableFq} (${cols.join(", ")}) VALUES (${placeholders})`;
    await query(insSql, vals);
    await ensureRolesTable();
    const setRole = role && (role === "admin" || role === "hr") ? role : "hr";
    if (roleCol) {
      await query(`UPDATE ${tableFq} SET ${roleCol} = $1 WHERE lower(${identityCol}) = lower($2)`, [setRole, username]);
    } else {
      await setUserRole(username, setRole);
    }
    res.status(201).json({ status: "ok", user: { username } });
  } catch (err) {
    console.error("Add user failed", err.message);
    res.status(500).json({ error: `Add user error: ${err.message}` });
  }
});

app.post("/api/delete_user", async (req, res) => {
  try {
    const { actor, username } = req.body || {};
    if (!actor) return res.status(401).json({ error: "Actor required" });
    const actorRole = await getUserRole(actor);
    if (actorRole !== "admin") return res.status(403).json({ error: "Not authorized" });
    if (!username) return res.status(400).json({ error: "Username required" });
    const { tableFq, identityCol } = await getHrLoginMeta();
    if (!tableFq || !identityCol) return res.status(500).json({ error: "hrlogin table missing expected columns" });
    const delSql = `DELETE FROM ${tableFq} WHERE lower(${identityCol}) = lower($1)`;
    await query(delSql, [username]);
    await ensureRolesTable();
    await query(`DELETE FROM public.userroles WHERE lower(username) = lower($1)`, [username]);
    res.json({ status: "ok" });
  } catch (err) {
    console.error("Delete user failed", err.message);
    res.status(500).json({ error: `Delete user error: ${err.message}` });
  }
});

app.post("/api/set_role", async (req, res) => {
  try {
    const { actor, username, role } = req.body || {};
    if (!actor) return res.status(401).json({ error: "Actor required" });
    const actorRole = await getUserRole(actor);
    if (actorRole !== "admin") return res.status(403).json({ error: "Not authorized" });
    if (!username || !role) return res.status(400).json({ error: "Username and role required" });
    if (!["admin","hr"].includes(role)) return res.status(400).json({ error: "Invalid role" });
    await setUserRole(username, role);
    res.json({ status: "ok" });
  } catch (err) {
    console.error("Set role failed", err.message);
    res.status(500).json({ error: `Set role error: ${err.message}` });
  }
});

app.get("/api/users", async (_req, res) => {
  try {
    const { tableFq, identityCol, roleCol } = await getHrLoginMeta();
    if (!tableFq || !identityCol) return res.status(500).json({ error: "hrlogin table missing expected columns" });
    const sql = `SELECT ${identityCol} AS username${roleCol ? `, ${roleCol} AS role` : ""} FROM ${tableFq} ORDER BY ${identityCol}`;
    const { rows } = await query(sql);
    let rolesMap = {};
    if (!roleCol) {
      try {
        const r = await query(`SELECT username, role FROM public.userroles`);
        rolesMap = Object.fromEntries(r.rows.map(x => [String(x.username).toLowerCase(), String(x.role)]));
      } catch {}
    }
    const users = rows.map(r => {
      let rr = r.role;
      if (!rr && rolesMap[String(r.username).toLowerCase()]) rr = rolesMap[String(r.username).toLowerCase()];
      const norm = rr === undefined || rr === null ? null : String(rr).trim().toLowerCase();
      let role = null;
      if (norm) role = ["admin","administrator","superuser","true","1","yes","y"].includes(norm) ? "admin" : "hr";
      return { username: r.username, role };
    });
    res.json(users);
  } catch (err) {
    console.error("List users failed", err.message);
    res.status(500).json({ error: `Users error: ${err.message}` });
  }
});

// Serve React app for all non-API routes
app.get("*", (_req, res) => {
  const indexPath = path.join(frontendDistDir, "index.html");
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send("Frontend build not found. Run 'npm run build' in the frontend folder.");
  }
});

async function init() {
  try {
    await ensureRolesTable();
    await ensurePermissionsTable();
    await ensureBusinessTables();
  } catch (err) {
    console.error("Database initialization failed", err.message);
  }
  const port = process.env.PORT || 5001;
  app.listen(port, () => {
    console.log(`Appraisal Dashboard server running on http://localhost:${port}/`);
  });
}

init();

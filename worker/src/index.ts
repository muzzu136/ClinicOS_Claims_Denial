import { Hono } from "hono";
import { cors } from "hono/cors";
import OpenAI from "openai";

type Bindings = {
  COMPANY_ID: string;
  APP_BASE_URL: string;
  PUBLIC_SUBDOMAIN: string;
  ANALYTICS: AnalyticsEngineDataset;
  DB: D1Database;
  FILES_BUCKET: R2Bucket;
  LAUNCHYARD_API_KEY: string;
  LAUNCHYARD_API_BASE_URL: string;
  PM_ENCRYPTION_KEY: string | undefined;
  DRCHRONO_CLIENT_ID: string | undefined;
  DRCHRONO_CLIENT_SECRET: string | undefined;
};

// ─── Denial codes ─────────────────────────────────────────────────────────────
const DENIAL_CODES: Array<{ code: string; label: string }> = [
  { code: "CO-4",   label: "Service inconsistent with modifier" },
  { code: "CO-11",  label: "Diagnosis inconsistent with procedure" },
  { code: "CO-16",  label: "Claim lacks information needed for adjudication" },
  { code: "CO-22",  label: "Coordination of benefits" },
  { code: "CO-45",  label: "Charge exceeds fee schedule" },
  { code: "CO-50",  label: "Not covered - not deemed a medical necessity" },
  { code: "CO-97",  label: "Service already adjudicated" },
  { code: "CO-109", label: "Claim not covered by this payer" },
  { code: "CO-119", label: "Benefit maximum for this time period has been reached" },
  { code: "CO-151", label: "Payment adjusted because the payer deems information submitted does not support this level of service" },
  { code: "CO-167", label: "Diagnosis is not covered" },
  { code: "CO-170", label: "Payment adjusted for COB" },
  { code: "CO-197", label: "Precertification/authorization absent" },
  { code: "CO-236", label: "This procedure or procedure/modifier combination is not compatible with another procedure or procedure/modifier combination" },
  { code: "PR-1",   label: "Deductible amount" },
  { code: "PR-2",   label: "Coinsurance amount" },
  { code: "PR-3",   label: "Co-payment amount" },
  { code: "PR-96",  label: "Non-covered charge" },
  { code: "PR-204", label: "This service/equipment/drug is not covered under the patient's current benefit plan" },
  { code: "OA-23",  label: "Payment adjusted due to information provided by the member" },
  { code: "OA-18",  label: "Exact duplicate claim/service" },
  { code: "OA-109", label: "Claim not covered by this payer/contractor" },
  { code: "PI-15",  label: "Workers' compensation case settled" },
  { code: "PI-97",  label: "Payment is included in the allowance for another service/procedure" },
  { code: "N130",   label: "Consult your Remittance Advice or contact the payer's Customer Service" },
  { code: "N290",   label: "Missing/incomplete/invalid rendering provider primary identifier" },
];

// ─── Auth helpers ──────────────────────────────────────────────────────────────

function generateId(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password: string, salt: string): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 100000 },
    keyMaterial, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifyPassword(password: string, salt: string, hash: string): Promise<boolean> {
  const computed = await hashPassword(password, salt);
  if (computed.length !== hash.length) return false;
  // constant-time compare
  let diff = 0;
  for (let i = 0; i < computed.length; i++) diff |= computed.charCodeAt(i) ^ hash.charCodeAt(i);
  return diff === 0;
}

type SessionUser = {
  user_id: string;
  email: string;
  plan: string | null;
  role: string | null;
  account_id: string | null;
  name: string | null;
};

async function getSession(db: D1Database, sessionId: string): Promise<SessionUser | null> {
  if (!sessionId) return null;
  const now = Math.floor(Date.now() / 1000);
  const row = await db.prepare(
    "SELECT s.user_id, u.email, u.plan, u.role, u.account_id, u.name FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.expires_at > ?"
  ).bind(sessionId, now).first<SessionUser>();
  return row ?? null;
}

function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const part of cookieHeader.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    cookies[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return cookies;
}

async function getCurrentUser(c: { req: { header: (k: string) => string | undefined }, env: Bindings }): Promise<SessionUser | null> {
  const cookieHeader = c.req.header("cookie") || "";
  const cookies = parseCookies(cookieHeader);
  const sessionId = cookies["clinicios_session"];
  if (!sessionId) return null;
  return getSession(c.env.DB, sessionId);
}

// Returns the account_id for shared-data queries. For solo users (no account_id), falls back to user_id.
function effectiveAccountId(user: SessionUser): string {
  return user.account_id ?? user.user_id;
}

// Helper to build a WHERE clause that finds all data for a user's practice account
// For team users: includes all users in the same account. For solo users: just that user.
function accountFilter(user: SessionUser): { clause: string; param: string } {
  if (user.account_id) {
    return { clause: "user_id IN (SELECT id FROM users WHERE account_id = ?)", param: user.account_id };
  }
  return { clause: "user_id = ?", param: user.user_id };
}

function isProfessionalPlan(user: SessionUser | null): boolean {
  if (!user) return false;
  const plan = (user.plan || "").toLowerCase();
  return plan === "professional" || plan === "pro";
}

function canManageTeam(user: SessionUser | null): boolean {
  if (!user) return false;
  const role = (user.role || "").toLowerCase();
  return role === "owner" || role === "admin";
}

function isReadOnly(user: SessionUser | null): boolean {
  if (!user) return false;
  return (user.role || "").toLowerCase() === "readonly";
}

// Access levels: 'anonymous' | 'trial_active' | 'trial_expired' | 'paid'
type AccessLevel = 'anonymous' | 'trial_active' | 'trial_expired' | 'paid';

async function getUserAccessLevel(db: D1Database, userId: string | null): Promise<AccessLevel> {
  if (!userId) return 'anonymous';
  const row = await db.prepare("SELECT plan, trial_end FROM users WHERE id = ?")
    .bind(userId).first<{ plan: string | null; trial_end: number | null }>();
  if (!row) return 'anonymous';
  const plan = (row.plan || "").toLowerCase();
  const isPaid = plan === "starter" || plan === "growth" || plan === "professional" || plan === "pro";
  if (isPaid) return 'paid';
  const now = Math.floor(Date.now() / 1000);
  if (row.trial_end && row.trial_end > now) return 'trial_active';
  if (row.trial_end && row.trial_end <= now) return 'trial_expired';
  // No plan, no trial_end set — treat as active trial (new signup)
  return 'trial_active';
}

async function hashToken(token: string): Promise<string> {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(token));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ─── Nav builder ──────────────────────────────────────────────────────────────

function buildNav(user: SessionUser | null): string {
  const isProUser = isProfessionalPlan(user);
  const teamLink = isProUser ? `<a href="/settings/team">&#x1F465; Team</a> <a href="/settings/rules">&#x1F6E1; Rules</a>` : '';
  const authLinks = user
    ? `<li><a href="/my-claims" class="nav-link-highlight">My Claims</a></li>
       <li><a href="/appeal-generator" class="nav-link-highlight">Appeal Generator</a></li>
       <li class="nav-user-menu">
         <button class="nav-user-btn" onclick="this.closest('.nav-user-menu').classList.toggle('open')" type="button">
           <span class="nav-user-avatar">${user.email[0].toUpperCase()}</span>
           <span class="nav-user-email">${escHtml(user.email)}</span>
           <span>&#x25BE;</span>
         </button>
         <div class="nav-user-dropdown">
           <a href="/my-claims">&#x1F4CB; My Claims</a>
           <a href="/denial-tracker">&#x1F6AB; Denial Tracker</a>
           <a href="/appeal-generator">&#x270D; Appeal Generator</a>
           ${teamLink}
           <form method="POST" action="/logout" style="margin:0"><button type="submit" class="nav-dropdown-btn">&#x1F6AA; Sign Out</button></form>
         </div>
       </li>`
    : `<li><a href="/login">Sign In</a></li>`;
  return `<nav><div class="nav-container">
  <a href="/" class="logo"><div class="logo-icon">&#x26A1;</div>ClinicOS AI</a>
  <ul class="nav-links">
    <li><a href="/#how-it-works">How it Works</a></li>
    <li><a href="/pricing">Pricing</a></li>
    <li><a href="/#faq">FAQ</a></li>
    <li><a href="/scrubber" class="nav-link-highlight">Claim Scrubber</a></li>
    <li><a href="/denial-tracker" class="nav-link-highlight">Denial Tracker</a></li>
    <li><a href="/eligibility" class="nav-link-highlight">Eligibility</a></li>
    ${user ? `<li><a href="/appeals" class="nav-link-highlight">Appeals</a></li>` : ''}
    ${user ? `<li><a href="/reports" class="nav-link-highlight">Reports</a></li>` : ''}
    ${authLinks}
  </ul>
  ${user ? '' : '<a href="/login" class="nav-cta">Sign In &#x2197;</a>'}
</div></nav>
<style>
.nav-user-menu{position:relative}
.nav-user-btn{background:none;border:2px solid #e2e8f0;border-radius:8px;padding:.45rem .85rem;cursor:pointer;font-size:.9rem;font-weight:600;color:var(--navy);display:flex;align-items:center;gap:.4rem;transition:border-color .2s}
.nav-user-btn:hover{border-color:var(--electric-blue)}
.nav-user-avatar{width:26px;height:26px;background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));border-radius:50%;color:#fff;font-size:.75rem;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.nav-user-email{max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nav-user-dropdown{display:none;position:absolute;right:0;top:calc(100% + 8px);background:#fff;border:1px solid #e2e8f0;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.12);min-width:170px;z-index:9999;overflow:hidden}
.nav-user-menu.open .nav-user-dropdown{display:block}
.nav-user-dropdown a,.nav-dropdown-btn{display:block;padding:.75rem 1rem;color:#334155;text-decoration:none;font-size:.9rem;font-weight:500;transition:background .15s;background:none;border:none;width:100%;text-align:left;cursor:pointer;font-family:inherit}
.nav-user-dropdown a:hover,.nav-dropdown-btn:hover{background:#f8fafc;color:var(--electric-blue)}
</style>
<script>document.addEventListener('click',function(e){document.querySelectorAll('.nav-user-menu.open').forEach(function(m){if(!m.contains(e.target))m.classList.remove('open')})});</script>`;
}

function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ─── PM Encryption helpers ────────────────────────────────────────────────────

async function getPmKey(rawKey: string | undefined): Promise<CryptoKey> {
  // Use provided key or fallback to a deterministic dev key
  const keyMaterial = rawKey || "clinicos-pm-dev-fallback-key-32b!";
  const enc = new TextEncoder();
  // Derive a 32-byte key from whatever string we have
  const keyBytes = enc.encode(keyMaterial.padEnd(32, "0").slice(0, 32));
  return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptCredentials(data: unknown, rawKey: string | undefined): Promise<string> {
  const key = await getPmKey(rawKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  // Store as base64(iv):base64(ciphertext)
  const b64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  return b64(iv.buffer) + ":" + b64(ciphertext);
}

async function decryptCredentials(encrypted: string, rawKey: string | undefined): Promise<unknown> {
  const key = await getPmKey(rawKey);
  const [ivB64, ctB64] = encrypted.split(":");
  const b64d = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const iv = b64d(ivB64);
  const ciphertext = b64d(ctB64);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// ─── PM Plan check helper ─────────────────────────────────────────────────────

async function userCanConnectPm(db: D1Database, userId: string): Promise<boolean> {
  const row = await db.prepare("SELECT plan FROM users WHERE id = ?")
    .bind(userId).first<{ plan: string | null }>();
  if (!row) return false;
  const plan = (row.plan || "").toLowerCase();
  return plan === "growth" || plan === "professional" || plan === "pro";
}

// ─── PM fetch helpers ─────────────────────────────────────────────────────────

interface ScrubbableClaim {
  patient_id?: string;
  date_of_service?: string;
  cpt_code?: string;
  icd_code?: string;
  modifier?: string;
  units?: string;
  billed_amount?: string;
  payer?: string;
  [key: string]: string | undefined;
}

async function fetchKareoClaims(creds: { customer_key: string; api_key: string }, startDate: string, endDate: string): Promise<ScrubbableClaim[]> {
  const soapBody = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:kar="http://www.kareo.com/api/schemas/">
  <soap:Body>
    <kar:GetClaims>
      <kar:request>
        <kar:RequestHeader>
          <kar:CustomerKey>${creds.customer_key}</kar:CustomerKey>
          <kar:User><kar:APIKey>${creds.api_key}</kar:APIKey></kar:User>
        </kar:RequestHeader>
        <kar:Filter>
          <kar:StartDate>${startDate}</kar:StartDate>
          <kar:EndDate>${endDate}</kar:EndDate>
        </kar:Filter>
      </kar:request>
    </kar:GetClaims>
  </soap:Body>
</soap:Envelope>`;

  const resp = await fetch("https://webservice.kareo.com/services/soap/2.1/KareoServices.svc", {
    method: "POST",
    headers: { "Content-Type": "application/soap+xml; charset=utf-8", "SOAPAction": "GetClaims" },
    body: soapBody,
  });
  if (!resp.ok) throw new Error(`Kareo API error: ${resp.status}`);
  const xml = await resp.text();
  // Parse claims from XML
  const claims: ScrubbableClaim[] = [];
  const claimMatches = xml.matchAll(/<Claim[^>]*>([\s\S]*?)<\/Claim>/g);
  for (const m of claimMatches) {
    const block = m[1];
    const get = (tag: string) => { const r = block.match(new RegExp(`<${tag}[^>]*>([^<]*)<\/${tag}>`)); return r?.[1]?.trim() || ""; };
    claims.push({
      patient_id: get("PatientID") || get("PatientMRN") || get("PatientCaseID"),
      date_of_service: get("StartDate") || get("DateOfService"),
      cpt_code: get("ProcedureCode") || get("CPTCode"),
      icd_code: get("DiagnosisCode1") || get("ICDCode"),
      modifier: get("Modifier1"),
      units: get("Units"),
      billed_amount: get("BilledAmount") || get("ChargeAmount"),
      payer: get("PayerName") || get("InsuranceName"),
    });
  }
  return claims;
}

async function fetchAdvancedMDClaims(creds: { office_code: string; username: string; password: string; app_name: string }, startDate: string, endDate: string): Promise<ScrubbableClaim[]> {
  // Authenticate
  const authParams = new URLSearchParams({
    action: "loginstaff",
    officecode: creds.office_code,
    username: creds.username,
    password: creds.password,
    appname: creds.app_name,
  });
  const authResp = await fetch("https://providerapi.advancedmd.com/processrequest/AMDIsapi.dll", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: authParams.toString(),
  });
  if (!authResp.ok) throw new Error(`AdvancedMD auth error: ${authResp.status}`);
  const authData = await authResp.json() as { sessiontoken?: string; error?: string };
  if (!authData.sessiontoken) throw new Error(authData.error || "Authentication failed");

  // Fetch claims
  const claimParams = new URLSearchParams({
    action: "getclaimlist",
    officecode: creds.office_code,
    sessiontoken: authData.sessiontoken,
    startdate: startDate,
    enddate: endDate,
  });
  const claimResp = await fetch("https://providerapi.advancedmd.com/processrequest/AMDIsapi.dll", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: claimParams.toString(),
  });
  if (!claimResp.ok) throw new Error(`AdvancedMD claims error: ${claimResp.status}`);
  const data = await claimResp.json() as { claims?: Array<Record<string, string>> };
  const rawClaims = data.claims || [];
  return rawClaims.map(r => ({
    patient_id: r["patientid"] || r["chart_id"] || r["patient_id"],
    date_of_service: r["servicedate"] || r["dos"],
    cpt_code: r["cptcode"] || r["procedure_code"],
    icd_code: r["icd10"] || r["diagnosiscode"],
    modifier: r["modifier1"] || r["modifier"],
    units: r["units"] || r["quantity"],
    billed_amount: r["billedamt"] || r["charge_amount"],
    payer: r["insurancename"] || r["payer_name"],
  }));
}

async function refreshDrChronoToken(creds: { access_token: string; refresh_token: string; expires_at?: number }, clientId: string, clientSecret: string): Promise<{ access_token: string; refresh_token: string; expires_at: number }> {
  const params = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: creds.refresh_token,
    client_id: clientId,
    client_secret: clientSecret,
  });
  const resp = await fetch("https://drchrono.com/o/token/", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  if (!resp.ok) throw new Error("DrChrono token refresh failed");
  const data = await resp.json() as { access_token: string; refresh_token: string; expires_in: number };
  return {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_at: Math.floor(Date.now() / 1000) + (data.expires_in || 172800),
  };
}

async function fetchDrChronoClaims(creds: { access_token: string; refresh_token: string; expires_at?: number }, startDate: string, endDate: string, clientId: string, clientSecret: string): Promise<{ claims: ScrubbableClaim[]; newCreds: typeof creds }> {
  let activeCreds = { ...creds };
  // Refresh if expired or expiring within 5 min
  const now = Math.floor(Date.now() / 1000);
  if (!activeCreds.expires_at || activeCreds.expires_at < now + 300) {
    activeCreds = await refreshDrChronoToken(activeCreds, clientId, clientSecret);
  }
  const url = `https://app.drchrono.com/api/billing_profiles?date_of_service_min=${startDate}&date_of_service_max=${endDate}`;
  const resp = await fetch(url, {
    headers: { Authorization: `Bearer ${activeCreds.access_token}` },
  });
  if (!resp.ok) throw new Error(`DrChrono API error: ${resp.status}`);
  const data = await resp.json() as { results?: Array<Record<string, string>> };
  const results = data.results || [];
  const claims: ScrubbableClaim[] = results.map(r => ({
    patient_id: r["patient"] || r["patient_id"],
    date_of_service: r["date_of_service"],
    cpt_code: r["procedure_code"] || r["cpt_code"],
    icd_code: r["diagnosis_code"] || r["icd_code"],
    modifier: r["modifier1"],
    units: r["units"],
    billed_amount: r["billed_amount"],
    payer: r["payer_name"] || r["insurance"],
  }));
  return { claims, newCreds: activeCreds };
}

function claimsToCSV(claims: ScrubbableClaim[], source: string): string {
  const headers = ["patient_id", "date_of_service", "cpt_code", "icd10", "modifier", "units", "billed_amount", "payer_id", "source"];
  const rows = claims.map(c => [
    c.patient_id || "",
    c.date_of_service || "",
    c.cpt_code || "",
    c.icd_code || "",
    c.modifier || "",
    c.units || "",
    c.billed_amount || "",
    c.payer || "",
    source,
  ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(","));
  return [headers.join(","), ...rows].join("\n");
}

const app = new Hono<{ Bindings: Bindings }>();
app.use("/api/*", cors());

app.get("/api/healthz", (c) => c.json({ status: "ok" }));

// ─── PM API routes ────────────────────────────────────────────────────────────

// GET /api/pm/connections — list all PM connections for current user
app.get("/api/pm/connections", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  const rows = await c.env.DB.prepare(
    "SELECT system, connected_at, last_used_at FROM pm_connections WHERE user_id = ?"
  ).bind(user.user_id).all<{ system: string; connected_at: number; last_used_at: number | null }>();
  return c.json({ connections: rows.results || [] });
});

// POST /api/pm/kareo/connect — save Kareo credentials
app.post("/api/pm/kareo/connect", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  if (!(await userCanConnectPm(c.env.DB, user.user_id))) {
    return c.json({ error: "Upgrade to Growth or Professional to connect PM systems" }, 403);
  }
  const body = await c.req.json() as { customer_key?: string; api_key?: string };
  if (!body.customer_key || !body.api_key) return c.json({ error: "customer_key and api_key are required" }, 400);
  const encrypted = await encryptCredentials({ customer_key: body.customer_key, api_key: body.api_key }, c.env.PM_ENCRYPTION_KEY);
  const id = generateId();
  await c.env.DB.prepare(
    "INSERT INTO pm_connections (id, user_id, system, credentials_encrypted) VALUES (?, ?, 'kareo', ?) ON CONFLICT(user_id, system) DO UPDATE SET credentials_encrypted=excluded.credentials_encrypted, connected_at=unixepoch()"
  ).bind(id, user.user_id, encrypted).run();
  return c.json({ ok: true });
});

// POST /api/pm/advancedmd/connect — save AdvancedMD credentials
app.post("/api/pm/advancedmd/connect", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  if (!(await userCanConnectPm(c.env.DB, user.user_id))) {
    return c.json({ error: "Upgrade to Growth or Professional to connect PM systems" }, 403);
  }
  const body = await c.req.json() as { office_code?: string; username?: string; password?: string; app_name?: string };
  if (!body.office_code || !body.username || !body.password || !body.app_name) {
    return c.json({ error: "office_code, username, password, and app_name are required" }, 400);
  }
  const encrypted = await encryptCredentials({ office_code: body.office_code, username: body.username, password: body.password, app_name: body.app_name }, c.env.PM_ENCRYPTION_KEY);
  const id = generateId();
  await c.env.DB.prepare(
    "INSERT INTO pm_connections (id, user_id, system, credentials_encrypted) VALUES (?, ?, 'advancedmd', ?) ON CONFLICT(user_id, system) DO UPDATE SET credentials_encrypted=excluded.credentials_encrypted, connected_at=unixepoch()"
  ).bind(id, user.user_id, encrypted).run();
  return c.json({ ok: true });
});

// GET /api/pm/drchrono/connect — start DrChrono OAuth flow
app.get("/api/pm/drchrono/connect", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.redirect("/login?next=/scrubber");
  if (!(await userCanConnectPm(c.env.DB, user.user_id))) {
    return c.redirect("/scrubber?pm_error=upgrade");
  }
  const clientId = c.env.DRCHRONO_CLIENT_ID;
  if (!clientId) return c.redirect("/scrubber?pm_error=drchrono_not_configured");
  const redirectUri = `${c.env.APP_BASE_URL}/api/pm/drchrono/callback`;
  const authUrl = `https://drchrono.com/o/authorize/?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=billing:read`;
  return c.redirect(authUrl);
});

// GET /api/pm/drchrono/callback — handle DrChrono OAuth callback
app.get("/api/pm/drchrono/callback", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.redirect("/login?next=/scrubber");
  const url = new URL(c.req.url);
  const code = url.searchParams.get("code");
  const error = url.searchParams.get("error");
  if (error || !code) return c.redirect("/scrubber?pm_error=drchrono_denied");
  const clientId = c.env.DRCHRONO_CLIENT_ID;
  const clientSecret = c.env.DRCHRONO_CLIENT_SECRET;
  if (!clientId || !clientSecret) return c.redirect("/scrubber?pm_error=drchrono_not_configured");
  try {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: `${c.env.APP_BASE_URL}/api/pm/drchrono/callback`,
      client_id: clientId,
      client_secret: clientSecret,
    });
    const resp = await fetch("https://drchrono.com/o/token/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });
    if (!resp.ok) throw new Error("Token exchange failed");
    const data = await resp.json() as { access_token: string; refresh_token: string; expires_in: number };
    const creds = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: Math.floor(Date.now() / 1000) + (data.expires_in || 172800),
    };
    const encrypted = await encryptCredentials(creds, c.env.PM_ENCRYPTION_KEY);
    const id = generateId();
    await c.env.DB.prepare(
      "INSERT INTO pm_connections (id, user_id, system, credentials_encrypted) VALUES (?, ?, 'drchrono', ?) ON CONFLICT(user_id, system) DO UPDATE SET credentials_encrypted=excluded.credentials_encrypted, connected_at=unixepoch()"
    ).bind(id, user.user_id, encrypted).run();
    return c.redirect("/scrubber?pm_connected=drchrono");
  } catch {
    return c.redirect("/scrubber?pm_error=drchrono_token_failed");
  }
});

// POST /api/pm/disconnect — disconnect a PM system
app.post("/api/pm/disconnect", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  const body = await c.req.json() as { system?: string };
  if (!body.system || !["kareo","advancedmd","drchrono"].includes(body.system)) {
    return c.json({ error: "Invalid system" }, 400);
  }
  await c.env.DB.prepare("DELETE FROM pm_connections WHERE user_id = ? AND system = ?")
    .bind(user.user_id, body.system).run();
  return c.json({ ok: true });
});

// POST /api/pm/fetch-claims — fetch claims from a connected PM system and run through scrubber
app.post("/api/pm/fetch-claims", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  if (!(await userCanConnectPm(c.env.DB, user.user_id))) {
    return c.json({ error: "Upgrade to Growth or Professional to use PM imports" }, 403);
  }
  const body = await c.req.json() as { system?: string; days?: number; payer?: string };
  const system = body.system;
  const days = body.days || 7;
  const payer = body.payer || "general";
  if (!system || !["kareo","advancedmd","drchrono"].includes(system)) {
    return c.json({ error: "Invalid system" }, 400);
  }
  // Get the connection
  const conn = await c.env.DB.prepare("SELECT credentials_encrypted FROM pm_connections WHERE user_id = ? AND system = ?")
    .bind(user.user_id, system).first<{ credentials_encrypted: string }>();
  if (!conn) return c.json({ error: `${system} is not connected` }, 404);

  // Calculate date range
  const end = new Date();
  const start = new Date();
  start.setDate(start.getDate() - days);
  const fmt = (d: Date) => d.toISOString().split("T")[0];
  const startDate = fmt(start);
  const endDate = fmt(end);

  let claims: ScrubbableClaim[] = [];
  const systemLabel = system === "kareo" ? "Kareo" : system === "advancedmd" ? "AdvancedMD" : "DrChrono";

  try {
    const creds = await decryptCredentials(conn.credentials_encrypted, c.env.PM_ENCRYPTION_KEY);
    if (system === "kareo") {
      claims = await fetchKareoClaims(creds as { customer_key: string; api_key: string }, startDate, endDate);
    } else if (system === "advancedmd") {
      claims = await fetchAdvancedMDClaims(creds as { office_code: string; username: string; password: string; app_name: string }, startDate, endDate);
    } else if (system === "drchrono") {
      const clientId = c.env.DRCHRONO_CLIENT_ID;
      const clientSecret = c.env.DRCHRONO_CLIENT_SECRET;
      if (!clientId || !clientSecret) return c.json({ error: "DrChrono OAuth not configured" }, 500);
      const result = await fetchDrChronoClaims(creds as { access_token: string; refresh_token: string; expires_at?: number }, startDate, endDate, clientId, clientSecret);
      claims = result.claims;
      // Update stored creds if token was refreshed
      const refreshedCreds = result.newCreds;
      if ((refreshedCreds as { access_token: string }).access_token !== (creds as { access_token: string }).access_token) {
        const newEncrypted = await encryptCredentials(refreshedCreds, c.env.PM_ENCRYPTION_KEY);
        await c.env.DB.prepare("UPDATE pm_connections SET credentials_encrypted = ? WHERE user_id = ? AND system = 'drchrono'")
          .bind(newEncrypted, user.user_id).run();
      }
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    return c.json({ error: `Failed to fetch claims from ${systemLabel}: ${msg}` }, 500);
  }

  if (claims.length === 0) {
    return c.json({ error: `No claims found in ${systemLabel} for the last ${days} days` }, 404);
  }

  // Update last_used_at
  await c.env.DB.prepare("UPDATE pm_connections SET last_used_at = unixepoch() WHERE user_id = ? AND system = ?")
    .bind(user.user_id, system).run();

  // Convert to CSV and run through scrubber pipeline
  const csvContent = claimsToCSV(claims, systemLabel);
  const csvBlob = new Blob([csvContent], { type: "text/csv" });
  const csvFile = new File([csvBlob], `${systemLabel} Import`, { type: "text/csv" });

  // Call scrub internally — build a FormData and POST to /api/scrub
  // Instead, inline the scrub logic
  const formData = new FormData();
  formData.append("file", csvFile);
  formData.append("payer", payer);

  // Inline scrub — reuse the same scrub endpoint logic
  const scrubReq = new Request(`${c.env.APP_BASE_URL}/api/scrub`, {
    method: "POST",
    body: formData,
    headers: { cookie: c.req.header("cookie") || "" },
  });
  const scrubResp = await app.fetch(scrubReq, c.env, c.executionCtx);
  const scrubData = await scrubResp.json();
  return c.json({ ...scrubData as object, pm_source: systemLabel });
});

const SHARED_STYLES = `
:root{--navy:#0f172a;--navy-light:#1a2a47;--electric-blue:#0284c7;--electric-teal:#06b6d4;--white:#fff;--gray-light:#f8fafc;--gray-dark:#64748b;--success:#10b981}
*{margin:0;padding:0;box-sizing:border-box}html{scroll-behavior:smooth}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;line-height:1.6;color:#334155;background:#fff}
nav{background:#fff;border-bottom:1px solid #e2e8f0;position:sticky;top:0;z-index:1000}
.nav-container{max-width:1200px;margin:0 auto;padding:1rem 2rem;display:flex;justify-content:space-between;align-items:center}
.logo{display:flex;align-items:center;gap:.5rem;font-size:1.5rem;font-weight:700;color:var(--navy);text-decoration:none}
.logo-icon{width:24px;height:24px;background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));border-radius:6px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:14px}
.nav-links{display:flex;gap:2rem;list-style:none;align-items:center}
.nav-links a{text-decoration:none;color:var(--gray-dark);font-weight:500;transition:color .3s ease}
.nav-links a:hover{color:var(--electric-blue)}
.nav-link-highlight{color:var(--electric-blue)!important;font-weight:700!important}
.nav-cta{background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));color:#fff;padding:.75rem 1.5rem;border-radius:8px;text-decoration:none;font-weight:600;transition:transform .2s ease,box-shadow .2s ease;border:none;cursor:pointer;white-space:nowrap}
.nav-cta:hover{transform:translateY(-2px);box-shadow:0 12px 24px rgba(2,132,199,.3)}
.btn{padding:1rem 2rem;border-radius:8px;font-size:1rem;font-weight:600;text-decoration:none;transition:all .3s ease;border:2px solid transparent;cursor:pointer;display:inline-block}
.btn-primary{background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));color:#fff;border:none}
.btn-primary:hover{transform:translateY(-3px);box-shadow:0 16px 32px rgba(2,132,199,.4)}
.btn-secondary{background:#fff;color:var(--electric-blue);border:2px solid var(--electric-blue)}
.btn-secondary:hover{background:#f0f9ff;transform:translateY(-3px)}
footer{background:var(--navy);color:#fff;padding:3rem 2rem 1.5rem;margin-top:5rem}
.footer-container{max-width:1200px;margin:0 auto;display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:2rem;margin-bottom:2rem}
.footer-section h4{font-size:1rem;font-weight:700;margin-bottom:1rem}
.footer-section a{display:block;color:rgba(255,255,255,.8);text-decoration:none;margin-bottom:.5rem;transition:color .3s ease}
.footer-section a:hover{color:var(--electric-teal)}
.footer-bottom{border-top:1px solid rgba(255,255,255,.2);padding-top:2rem;text-align:center;color:rgba(255,255,255,.6);font-size:.9rem}
.footer-logo{display:flex;align-items:center;gap:.5rem;margin-bottom:1rem}
.footer-tagline{color:rgba(255,255,255,.8);font-size:.95rem;margin-bottom:1rem}
@media(max-width:768px){.nav-links{display:none}}
`;

// NAV is now dynamic — use buildNav(user) in each route handler
const NAV = buildNav(null); // static fallback (used for pages that don't yet call getCurrentUser)

const FOOTER = `<footer><div class="footer-container">
  <div class="footer-section"><div class="footer-logo"><div class="logo-icon">&#x26A1;</div><strong>ClinicOS AI</strong></div><p class="footer-tagline">AI-powered claim scrubbing for independent practices.</p></div>
  <div class="footer-section"><h4>Product</h4><a href="/#how-it-works">How It Works</a><a href="/pricing">Pricing</a><a href="/scrubber">Claim Scrubber</a></div>
  <div class="footer-section"><h4>Legal</h4><a href="#">Privacy Policy</a><a href="#">Terms of Service</a><a href="#">HIPAA Compliance</a></div>
  <div class="footer-section"><h4>Contact</h4><a href="mailto:hello@clinicosai.com">hello@clinicosai.com</a></div>
</div><div class="footer-bottom"><p>&copy; 2024 ClinicOS AI. All rights reserved. Made with &#x2764;&#xFE0F; using <a href="https://launchyard.dev" style="color:var(--electric-teal);text-decoration:none;">Launchyard</a>.</p></div></footer>`;

// ─── Pricing Page (fully server-rendered, zero client-side content injection) ──

app.get("/pricing", async (c) => {
  const user = await getCurrentUser(c);
  const nav = buildNav(user);

  const CHECK = `<span style="color:#10b981;font-weight:700;font-size:1.1rem;flex-shrink:0;">&#10003;</span>`;
  const LOCK  = `<span style="color:#cbd5e1;font-size:1rem;flex-shrink:0;">&#128274;</span>`;

  function featureRow(icon: string, text: string) {
    return `<li style="display:flex;align-items:flex-start;gap:.65rem;padding:.6rem 0;border-bottom:1px solid #f1f5f9;font-size:.93rem;color:#334155;line-height:1.45;">${icon}<span>${text}</span></li>`;
  }

  function badge(text: string, color: string, bg: string) {
    return `<span style="display:inline-block;background:${bg};color:${color};font-size:.7rem;font-weight:700;padding:.15rem .5rem;border-radius:20px;margin-left:.4rem;vertical-align:middle;">${text}</span>`;
  }

  const starterFeatures = [
    featureRow(CHECK, "Claim scrubber — first 3 flagged results per upload"),
    featureRow(CHECK, "General claim rules: missing fields, CPT/ICD-10, modifiers, duplicates"),
    featureRow(CHECK, "User account and claim history"),
    featureRow(CHECK, "Denial tracker"),
    featureRow(CHECK, "Denial rate benchmarking vs industry average"),
    featureRow(CHECK, "Secure login and password reset"),
    featureRow(LOCK, "Full unlimited scrubber"),
    featureRow(LOCK, "Payer-specific rules"),
    featureRow(LOCK, "Appeal letter generator"),
    featureRow(LOCK, "EHR import"),
    featureRow(LOCK, "Eligibility check"),
    featureRow(LOCK, "Team seats"),
    featureRow(LOCK, "Bulk scrubbing"),
    featureRow(LOCK, "Custom rules"),
    featureRow(LOCK, "Appeal tracking"),
    featureRow(LOCK, "Monthly billing health report"),
  ].join("");

  const growthFeatures = [
    featureRow(CHECK, "Everything in Starter"),
    featureRow(CHECK, "Full unlimited scrubber results — no cap"),
    featureRow(CHECK, "Payer-specific rule profiles (Medicare, Medicaid, BCBS, United, Aetna, Cigna, Humana)"),
    featureRow(CHECK, `Appeal letter generator — AI-drafted letters for 26+ denial codes`),
    featureRow(CHECK, `EHR / PM system import — Kareo, AdvancedMD${badge("DrChrono — Coming Soon","#7c3aed","#ede9fe")}`),
    featureRow(CHECK, `Real-time eligibility check${badge("Demo Mode","#d97706","#fef3c7")}`),
    featureRow(LOCK, "Team seats"),
    featureRow(LOCK, "Bulk scrubbing"),
    featureRow(LOCK, "Custom rules"),
    featureRow(LOCK, "Appeal tracking"),
    featureRow(LOCK, "Monthly billing health report"),
  ].join("");

  const proFeatures = [
    featureRow(CHECK, "Everything in Growth"),
    featureRow(CHECK, "Multi-user team seats — up to 5 users, 3 roles (Admin, Biller, Read-only)"),
    featureRow(CHECK, "Bulk claim scrubbing — up to 10 CSV files, consolidated batch report"),
    featureRow(CHECK, "Custom denial rules — encode your own payer-specific rules"),
    featureRow(CHECK, "Automated appeal tracking — full lifecycle from sent to resolved"),
    featureRow(CHECK, "Monthly billing health report — auto-generated PDF on the 1st"),
    featureRow(CHECK, "Priority support"),
  ].join("");

  function card(name: string, price: string, subtitle: string, features: string, link: string, featured: boolean) {
    const borderStyle = featured
      ? "border:2.5px solid #0284c7;box-shadow:0 20px 40px rgba(2,132,199,.18);"
      : "border:2px solid #e2e8f0;";
    const mostPopular = featured
      ? `<div style="position:absolute;top:-14px;left:50%;transform:translateX(-50%);background:linear-gradient(135deg,#0284c7,#06b6d4);color:#fff;font-size:.75rem;font-weight:700;padding:.3rem .9rem;border-radius:20px;white-space:nowrap;">Most Popular</div>`
      : "";
    return `<div style="background:#fff;${borderStyle}border-radius:14px;padding:2.2rem 2rem;text-align:center;position:relative;display:flex;flex-direction:column;">
  ${mostPopular}
  <h3 style="font-size:1.4rem;color:#0f172a;font-weight:700;margin-bottom:.3rem;">${name}</h3>
  <div style="font-size:2.4rem;font-weight:800;color:#0284c7;margin:.6rem 0 .2rem;">${price}<span style="font-size:1rem;font-weight:500;color:#64748b;">/mo</span></div>
  <p style="color:#64748b;font-size:.9rem;margin-bottom:1.5rem;">${subtitle}</p>
  <ul style="list-style:none;margin-bottom:1.8rem;text-align:left;flex:1;">${features}</ul>
  <a href="${link}" style="display:block;background:linear-gradient(135deg,#0284c7,#06b6d4);color:#fff;padding:.9rem 1.5rem;border-radius:8px;font-weight:700;font-size:1rem;text-decoration:none;text-align:center;transition:opacity .2s;" onmouseover="this.style.opacity='.87'" onmouseout="this.style.opacity='1'">Start Free Trial →</a>
  <p style="font-size:.78rem;color:#94a3b8;margin-top:.6rem;">14-day free trial · No credit card required</p>
</div>`;
  }

  // Comparison table helpers
  const YES = `<td style="text-align:center;padding:.7rem .5rem;color:#10b981;font-size:1.15rem;font-weight:700;">&#10003;</td>`;
  const NO  = `<td style="text-align:center;padding:.7rem .5rem;color:#cbd5e1;font-size:1rem;">&#10005;</td>`;
  function sectionHeader(label: string) {
    return `<tr><td colspan="4" style="background:#f8fafc;padding:.7rem 1rem;font-weight:700;color:#0f172a;font-size:.85rem;text-transform:uppercase;letter-spacing:.05em;border-top:2px solid #e2e8f0;">${label}</td></tr>`;
  }
  function row(feature: string, s: boolean, g: boolean, p: boolean) {
    return `<tr style="border-bottom:1px solid #f1f5f9;">
      <td style="padding:.7rem 1rem;font-size:.93rem;color:#334155;">${feature}</td>
      ${s ? YES : NO}${g ? YES : NO}${p ? YES : NO}
    </tr>`;
  }

  const comparisonTable = `
<div style="overflow-x:auto;margin-top:3.5rem;">
<table style="width:100%;border-collapse:collapse;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.07);">
  <thead>
    <tr style="background:linear-gradient(135deg,#0f172a,#1a2a47);">
      <th style="padding:1rem 1.2rem;text-align:left;color:#fff;font-weight:700;font-size:.95rem;">Feature</th>
      <th style="padding:1rem .8rem;text-align:center;color:#fff;font-weight:700;font-size:.95rem;">Starter<br><span style="font-weight:400;font-size:.82rem;opacity:.8;">$99/mo</span></th>
      <th style="padding:1rem .8rem;text-align:center;color:#06b6d4;font-weight:700;font-size:.95rem;">Growth<br><span style="font-weight:400;font-size:.82rem;opacity:.8;color:#fff;">$299/mo</span></th>
      <th style="padding:1rem .8rem;text-align:center;color:#fff;font-weight:700;font-size:.95rem;">Professional<br><span style="font-weight:400;font-size:.82rem;opacity:.8;">$599/mo</span></th>
    </tr>
  </thead>
  <tbody>
    ${sectionHeader("Claim Scrubbing")}
    ${row("General claim rules (missing fields, CPT/ICD-10, modifiers, duplicates)", true, true, true)}
    ${row("Claim scrubber — limited (3 flagged results per upload)", true, false, false)}
    ${row("Full unlimited scrubber results", false, true, true)}
    ${row("Payer-specific rule profiles (Medicare, Medicaid, BCBS, Aetna, etc.)", false, true, true)}
    ${row("Bulk claim scrubbing — up to 10 CSV files", false, false, true)}
    ${row("Custom denial rules", false, false, true)}
    ${sectionHeader("Denial Management")}
    ${row("Denial tracker", true, true, true)}
    ${row("Denial rate benchmarking vs industry average", true, true, true)}
    ${sectionHeader("Appeals")}
    ${row("Appeal letter generator (AI-drafted, 26+ denial codes)", false, true, true)}
    ${row("Automated appeal tracking — full lifecycle", false, false, true)}
    ${sectionHeader("Integrations")}
    ${row("User account and claim history", true, true, true)}
    ${row("EHR / PM import — Kareo, AdvancedMD", false, true, true)}
    ${row("DrChrono OAuth (coming soon)", false, true, true)}
    ${row("Real-time eligibility check", false, true, true)}
    ${sectionHeader("Team &amp; Admin")}
    ${row("Multi-user team seats (up to 5 users)", false, false, true)}
    ${row("Role management (Admin, Biller, Read-only)", false, false, true)}
    ${sectionHeader("Reporting")}
    ${row("Monthly billing health report (auto PDF)", false, false, true)}
    ${row("Consolidated batch report", false, false, true)}
    ${sectionHeader("Support")}
    ${row("Standard support", true, true, true)}
    ${row("Priority support", false, false, true)}
  </tbody>
</table>
</div>`;

  const faqItems = [
    { q: "Is there a free trial?", a: "Yes — all plans include a 14-day free trial. Your card is not charged until the trial ends, and you can cancel anytime before that." },
    { q: "Can I switch plans?", a: "Yes. You can upgrade or downgrade at any time from your account settings. Changes take effect immediately; billing is prorated." },
    { q: "Is it HIPAA compliant?", a: "Yes. All data is encrypted at rest and in transit using AES-256 and TLS 1.3. A Business Associate Agreement (BAA) is available on all plans at no extra charge." },
    { q: "Which EHR systems do you support?", a: "Kareo/Tebra and AdvancedMD are fully live and available on Growth and Professional plans. DrChrono OAuth integration is in active development and coming soon." },
    { q: "What denial codes does the appeal generator cover?", a: "The appeal generator covers 26+ codes including CO-4, CO-11, CO-97, PR-96, CO-45, PR-1, CO-16, CO-22, CO-50, OA-18, OA-23, and all major CARCs and RARCs. New codes are added regularly." },
  ].map(({q, a}) => `
<details style="background:#fff;border:1.5px solid #e2e8f0;border-radius:10px;padding:1.2rem 1.5rem;margin-bottom:.85rem;">
  <summary style="font-weight:700;color:#0f172a;cursor:pointer;font-size:1rem;list-style:none;display:flex;justify-content:space-between;align-items:center;">
    ${q}
    <span style="font-size:1.2rem;color:#0284c7;margin-left:1rem;flex-shrink:0;">&#43;</span>
  </summary>
  <p style="margin-top:.85rem;color:#475569;font-size:.95rem;line-height:1.7;">${a}</p>
</details>`).join("");

  const trustBar = `
<div style="display:flex;flex-wrap:wrap;justify-content:center;gap:1.5rem;margin-top:3rem;">
  ${["&#x1F512; HIPAA Secure","&#x1F4CB; BAA Included","&#x1F4C5; No Long-Term Contracts","&#x274C; Cancel Anytime"].map(t =>
    `<div style="background:#f0fdf4;border:1.5px solid #bbf7d0;border-radius:10px;padding:.75rem 1.4rem;font-size:.9rem;font-weight:600;color:#166534;">${t}</div>`
  ).join("")}
</div>`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pricing — ClinicOS AI</title>
<style>
${SHARED_STYLES}
.section{padding:4rem 2rem}
.container{max-width:1140px;margin:0 auto}
.section-title{font-size:2.2rem;font-weight:800;color:#0f172a;margin-bottom:.6rem}
.section-subtitle{color:#64748b;font-size:1.05rem;max-width:600px;margin:0 auto 0}
.pricing-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:2rem;margin-top:2.8rem}
@media(max-width:900px){.pricing-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
${nav}
<main>
  <!-- Hero -->
  <section style="background:linear-gradient(135deg,#0f172a 0%,#1a2a47 100%);padding:5rem 2rem;text-align:center;color:#fff;">
    <div class="container">
      <p style="color:#06b6d4;font-weight:700;font-size:.95rem;letter-spacing:.1em;text-transform:uppercase;margin-bottom:.8rem;">Simple, Transparent Pricing</p>
      <h1 style="font-size:2.8rem;font-weight:800;margin-bottom:1rem;line-height:1.2;">Pick the plan that fits your practice</h1>
      <p style="color:rgba(255,255,255,.75);font-size:1.1rem;max-width:550px;margin:0 auto;">14-day free trial on every plan. No credit card required. Cancel anytime.</p>
    </div>
  </section>

  <!-- Pricing Cards -->
  <section class="section" style="background:#f8fafc;">
    <div class="container">
      <div class="pricing-grid">
        ${card("Starter","$99","Perfect for getting started",starterFeatures,"https://company-builder-api-hzcthfunbq-uc.a.run.app/v1/public/checkout/01KTR8VRGZAG37J1DNPJ4P2TC2?trial_days=14",false)}
        ${card("Growth","$299","Full tools for one active biller",growthFeatures,"https://company-builder-api-hzcthfunbq-uc.a.run.app/v1/public/checkout/01KTR8VS68PNQB21BSF4M16AQF?trial_days=14",true)}
        ${card("Professional","$599","Your whole team, end-to-end",proFeatures,"https://company-builder-api-hzcthfunbq-uc.a.run.app/v1/public/checkout/01KTR8VSWSFB39X1ND8K338TSZ?trial_days=14",false)}
      </div>
    </div>
  </section>

  <!-- Trust Bar -->
  <section class="section" style="padding:2.5rem 2rem;background:#fff;border-top:1px solid #e2e8f0;border-bottom:1px solid #e2e8f0;">
    <div class="container" style="text-align:center;">
      ${trustBar}
    </div>
  </section>

  <!-- Comparison Table -->
  <section class="section">
    <div class="container">
      <h2 class="section-title" style="text-align:center;">Full feature comparison</h2>
      ${comparisonTable}
    </div>
  </section>

  <!-- FAQ -->
  <section class="section" style="background:#f8fafc;">
    <div class="container" style="max-width:740px;">
      <h2 class="section-title" style="text-align:center;margin-bottom:2rem;">Frequently asked questions</h2>
      ${faqItems}
    </div>
  </section>

  <!-- CTA -->
  <section class="section" style="background:linear-gradient(135deg,#0284c7,#06b6d4);text-align:center;color:#fff;padding:4rem 2rem;">
    <div class="container">
      <h2 style="font-size:2rem;font-weight:800;margin-bottom:1rem;">Ready to cut your denial rate?</h2>
      <p style="opacity:.9;font-size:1.05rem;margin-bottom:2rem;">Start your free 14-day trial today. No credit card required.</p>
      <div style="display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;">
        <a href="https://company-builder-api-hzcthfunbq-uc.a.run.app/v1/public/checkout/01KTR8VS68PNQB21BSF4M16AQF?trial_days=14" style="background:#fff;color:#0284c7;padding:1rem 2rem;border-radius:8px;font-weight:700;text-decoration:none;font-size:1rem;">Start Free Trial — Growth</a>
        <a href="/signup" style="background:transparent;color:#fff;padding:1rem 2rem;border-radius:8px;font-weight:700;text-decoration:none;font-size:1rem;border:2px solid rgba(255,255,255,.6);">Create Account</a>
      </div>
    </div>
  </section>
</main>
${FOOTER}
</body>
</html>`;

  return c.html(html);
});

// ─── Home Page ─────────────────────────────────────────────────────────────────
app.get("/", async (c) => {
  const user = await getCurrentUser(c);
  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ClinicOS AI - AI-Powered Medical Billing Claim Scrubber</title>
<style>
${SHARED_STYLES}
.hero{max-width:1200px;margin:0 auto;padding:6rem 2rem;text-align:center}
.hero h1{font-size:3.5rem;font-weight:800;line-height:1.1;color:var(--navy);margin-bottom:1.5rem;max-width:900px;margin-left:auto;margin-right:auto}
.hero .subheadline{font-size:1.25rem;color:var(--gray-dark);max-width:800px;margin:0 auto 2.5rem;line-height:1.8}
.hero-ctas{display:flex;gap:1rem;justify-content:center;margin-bottom:2rem;flex-wrap:wrap}
.hero-social-proof{color:var(--gray-dark);font-size:.95rem;font-weight:500}
.stats-bar{background:linear-gradient(135deg,var(--navy),var(--navy-light));color:#fff;padding:3rem 2rem}
.stats-container{max-width:1200px;margin:0 auto;display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:3rem}
.stat{display:flex;gap:1.5rem;align-items:flex-start}
.stat-icon{width:48px;height:48px;background:rgba(6,182,212,.2);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;flex-shrink:0}
.stat-content h3{font-size:1.1rem;margin-bottom:.5rem;font-weight:600}.stat-content p{font-size:.9rem;color:rgba(255,255,255,.8)}
.section{max-width:1200px;margin:0 auto;padding:5rem 2rem}
.section-title{font-size:2.5rem;font-weight:800;text-align:center;color:var(--navy);margin-bottom:3rem}
.steps-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:2.5rem}
.step{text-align:center}
.step-number{width:60px;height:60px;background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));border-radius:50%;color:#fff;font-size:2rem;font-weight:700;display:flex;align-items:center;justify-content:center;margin:0 auto 1.5rem}
.step h3{font-size:1.25rem;color:var(--navy);margin-bottom:1rem;font-weight:700}.step p{color:var(--gray-dark);line-height:1.8}
.features-bg{background:var(--gray-light);padding:5rem 2rem}
.features-inner{max-width:1200px;margin:0 auto}
.features-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:2rem}
.feature-card{background:#fff;padding:2rem;border-radius:12px;border:1px solid #e2e8f0;transition:all .3s ease;text-align:center}
.feature-card:hover{transform:translateY(-8px);box-shadow:0 20px 40px rgba(2,132,199,.1);border-color:var(--electric-blue)}
.feature-icon{width:50px;height:50px;background:linear-gradient(135deg,rgba(2,132,199,.2),rgba(6,182,212,.2));border-radius:10px;display:flex;align-items:center;justify-content:center;margin:0 auto 1rem;font-size:1.5rem}
.feature-card h4{font-size:1.1rem;color:var(--navy);margin-bottom:.5rem;font-weight:700}.feature-card p{color:var(--gray-dark);font-size:.95rem;line-height:1.6}
.pricing-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:2rem;margin-top:3rem}
.pricing-card{background:#fff;border:2px solid #e2e8f0;border-radius:12px;padding:2.5rem;text-align:center;transition:all .3s ease;position:relative}
.pricing-card.featured{border-color:var(--electric-blue);box-shadow:0 20px 40px rgba(2,132,199,.15)}
.badge{position:absolute;top:-12px;right:20px;background:var(--electric-blue);color:#fff;padding:.5rem 1rem;border-radius:20px;font-size:.8rem;font-weight:700;text-transform:uppercase}
.pricing-card h3{font-size:1.5rem;color:var(--navy);margin-bottom:.5rem;font-weight:700}
.price{font-size:3rem;font-weight:800;color:var(--electric-blue);margin:1rem 0}
.price-desc{color:var(--gray-dark);font-size:.9rem;margin-bottom:2rem}
.pricing-features{list-style:none;margin-bottom:2rem;text-align:left}
.pricing-features li{padding:.75rem 0;color:var(--gray-dark);font-size:.95rem;border-bottom:1px solid #e2e8f0;display:flex;align-items:center;gap:.75rem}
.pricing-features li:last-child{border-bottom:none}
.check-icon{width:20px;height:20px;background:var(--success);color:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.8rem;font-weight:700;flex-shrink:0}
.waitlist-section{background:linear-gradient(135deg,var(--navy),var(--navy-light));color:#fff;padding:5rem 2rem;text-align:center}
.waitlist-inner{max-width:600px;margin:0 auto}
.waitlist-inner h2{font-size:2.5rem;font-weight:800;margin-bottom:1rem}
.waitlist-inner .subheadline{color:rgba(255,255,255,.9);margin-bottom:2rem}
.try-free-cta{background:rgba(255,255,255,.1);border:2px solid rgba(255,255,255,.3);border-radius:12px;padding:1.5rem 2rem;margin-bottom:2.5rem}
.try-free-cta p{color:rgba(255,255,255,.9);margin-bottom:1rem;font-size:1.1rem}
.waitlist-form{display:flex;gap:.75rem;margin-bottom:1rem}
.waitlist-form input{flex:1;padding:1rem;border:none;border-radius:8px;font-size:1rem;font-family:inherit}
.waitlist-form button{padding:1rem 2rem;background:#fff;color:var(--electric-blue);border:none;border-radius:8px;font-weight:600;cursor:pointer}
.waitlist-success{display:none;color:#34d399;font-weight:600;margin-top:1rem}
.faq-container{max-width:700px;margin:0 auto}
.faq-item{margin-bottom:1rem;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden}
.faq-question{background:var(--gray-light);padding:1.5rem;cursor:pointer;display:flex;justify-content:space-between;align-items:center;font-weight:600;color:var(--navy)}
.faq-toggle{font-size:1.5rem;transition:transform .3s ease;color:var(--electric-blue)}
.faq-item.open .faq-toggle{transform:rotate(180deg)}
.faq-answer{display:none;padding:1.5rem;color:var(--gray-dark);line-height:1.8;background:#fff}
.faq-item.open .faq-answer{display:block}
@media(max-width:768px){.hero h1{font-size:2rem}.hero .subheadline{font-size:1rem}.hero-ctas{flex-direction:column}.btn{width:100%}.section-title{font-size:1.75rem}.waitlist-form{flex-direction:column}}
</style>
</head>
<body>
${buildNav(user)}
<section class="hero">
  <h1>Stop Losing Money to Claim Denials.</h1>
  <p class="subheadline">ClinicOS AI is like Grammarly for your medical billing &#x2014; it catches errors, flags denials before they happen, and drafts your appeals automatically.</p>
  <div class="hero-ctas">
    <a href="/scrubber" class="btn btn-primary">Try the Claim Scrubber Free &#x2197;</a>
    <button class="btn btn-secondary" onclick="document.getElementById('how-it-works').scrollIntoView({behavior:'smooth'})">See How It Works</button>
  </div>
  <p class="hero-social-proof">&#x2713; Built for independent clinics, dental practices &amp; urgent care centers. No signup required.</p>
</section>
<section class="stats-bar">
  <div class="stats-container">
    <div class="stat"><div class="stat-icon">&#x1F4CA;</div><div class="stat-content"><h3>30% of claims</h3><p>are denied on first submission</p></div></div>
    <div class="stat"><div class="stat-icon">&#x1F4B0;</div><div class="stat-content"><h3>$262B lost</h3><p>annually to claim denials</p></div></div>
    <div class="stat"><div class="stat-icon">&#x26A0;&#xFE0F;</div><div class="stat-content"><h3>60% of denied claims</h3><p>are never resubmitted</p></div></div>
  </div>
</section>
<section class="section" id="how-it-works">
  <h2 class="section-title">How It Works</h2>
  <div class="steps-grid">
    <div class="step"><div class="step-number">1</div><h3>Upload Your Claims</h3><p>Drop in a CSV export from your billing software. No EHR integration required.</p></div>
    <div class="step"><div class="step-number">2</div><h3>AI Scrubs for Errors</h3><p>ClinicOS AI scans for missing modifiers, invalid CPT combos, duplicate claims, and 50+ denial triggers.</p></div>
    <div class="step"><div class="step-number">3</div><h3>Fix &amp; Resubmit</h3><p>Get a clean claims report with suggested fixes for anything that needs attention.</p></div>
  </div>
</section>
<section class="features-bg">
  <div class="features-inner">
    <h2 class="section-title">Powerful Features Built for Your Practice</h2>
    <div class="features-grid">
      <div class="feature-card"><div class="feature-icon">&#x2713;</div><h4>Pre-Submission Claim Scrubbing</h4><p>Catch billing errors before they become costly denials.</p></div>
      <div class="feature-card"><div class="feature-icon">&#x1F50D;</div><h4>CPT &amp; Modifier Validation</h4><p>Validate every code combination against payer rules.</p></div>
      <div class="feature-card"><div class="feature-icon">&#x1F504;</div><h4>Duplicate Claim Detection</h4><p>Prevent accidental duplicate submissions that trigger audits.</p></div>
      <div class="feature-card"><div class="feature-icon">&#x1F4C8;</div><h4>Denial Pattern Analytics</h4><p>Track why claims fail and identify systemic issues.</p></div>
      <div class="feature-card"><div class="feature-icon">&#x270D;&#xFE0F;</div><h4>AI-Drafted Appeal Letters</h4><p>Generate compelling appeals in seconds with legal language.</p></div>
      <div class="feature-card"><div class="feature-icon">&#x1F517;</div><h4>Works With Any Billing Software</h4><p>No vendor lock-in. Import from Athena, eClinicalWorks, Dentrix, more.</p></div>
    </div>
  </div>
</section>
<section class="section" id="pricing">
  <h2 class="section-title">Simple, Transparent Pricing</h2>
  <div class="pricing-cards">
    <div class="pricing-card">
      <h3>Starter</h3><div class="price">$99<span style="font-size:1.5rem">/mo</span></div><p class="price-desc">Perfect for small practices</p>
      <ul class="pricing-features"><li><span class="check-icon">&#x2713;</span>Up to 200 claims/month</li><li><span class="check-icon">&#x2713;</span>Claim scrubbing</li><li><span class="check-icon">&#x2713;</span>Error reports</li><li><span class="check-icon">&#x2713;</span>Email support</li></ul>
      <a href="https://company-builder-api-hzcthfunbq-uc.a.run.app/v1/public/checkout/01KTR8VRGZAG37J1DNPJ4P2TC2?trial_days=14" class="btn btn-primary pricing-cta" style="display:block" onclick="pricingClick(this)">Start Free Trial</a>
    </div>
    <div class="pricing-card featured">
      <div class="badge">Most Popular</div>
      <h3>Growth</h3><div class="price">$299<span style="font-size:1.5rem">/mo</span></div><p class="price-desc">For growing practices</p>
      <ul class="pricing-features"><li><span class="check-icon">&#x2713;</span>Up to 1,000 claims/month</li><li><span class="check-icon">&#x2713;</span>Denial tracking</li><li><span class="check-icon">&#x2713;</span>Appeal templates</li><li><span class="check-icon">&#x2713;</span>Priority support</li></ul>
      <a href="https://company-builder-api-hzcthfunbq-uc.a.run.app/v1/public/checkout/01KTR8VS68PNQB21BSF4M16AQF?trial_days=14" class="btn btn-primary pricing-cta" style="display:block" onclick="pricingClick(this)">Start Free Trial</a>
    </div>
    <div class="pricing-card">
      <h3>Professional</h3><div class="price">$599<span style="font-size:1.5rem">/mo</span></div><p class="price-desc">Enterprise-grade solution</p>
      <ul class="pricing-features"><li><span class="check-icon">&#x2713;</span>Unlimited claims</li><li><span class="check-icon">&#x2713;</span>AI appeal automation</li><li><span class="check-icon">&#x2713;</span>Dedicated onboarding</li><li><span class="check-icon">&#x2713;</span>API access</li></ul>
      <a href="https://company-builder-api-hzcthfunbq-uc.a.run.app/v1/public/checkout/01KTR8VSWSFB39X1ND8K338TSZ?trial_days=14" class="btn btn-primary pricing-cta" style="display:block" onclick="pricingClick(this)">Start Free Trial</a>
    </div>
  </div>
</section>
<section class="waitlist-section" id="waitlist">
  <div class="waitlist-inner">
    <div class="try-free-cta">
      <p>Ready to see it in action? No account needed.</p>
      <a href="/scrubber" class="btn btn-primary">Try the Claim Scrubber Free &#x2192;</a>
    </div>
    <h2>Join the Waitlist</h2>
    <p class="subheadline">Early access members get 60 days free and locked-in launch pricing.</p>
    <form class="waitlist-form" id="waitlistForm" onsubmit="handleWaitlist(event)">
      <input type="email" placeholder="your@clinic.com" required>
      <button type="submit">Join Waitlist</button>
    </form>
    <div class="waitlist-success" id="waitlistSuccess">&#x2713; You're on the list! We'll be in touch soon.</div>
  </div>
</section>
<section class="section" id="faq">
  <h2 class="section-title">Frequently Asked Questions</h2>
  <div class="faq-container">
    <div class="faq-item"><div class="faq-question" onclick="this.parentElement.classList.toggle('open')"><span>Do I need to switch my billing software?</span><span class="faq-toggle">&#x25BC;</span></div><div class="faq-answer">No. ClinicOS AI works with any billing platform. Simply export your claims as a CSV file and upload them.</div></div>
    <div class="faq-item"><div class="faq-question" onclick="this.parentElement.classList.toggle('open')"><span>Is patient data secure?</span><span class="faq-toggle">&#x25BC;</span></div><div class="faq-answer">Yes, we are HIPAA-compliant. We only need billing information necessary to validate claims. We use industry-standard encryption and never share your data.</div></div>
    <div class="faq-item"><div class="faq-question" onclick="this.parentElement.classList.toggle('open')"><span>How long does scrubbing take?</span><span class="faq-toggle">&#x25BC;</span></div><div class="faq-answer">Under 60 seconds for most claim batches. Our AI processes claims simultaneously so even larger uploads are analyzed quickly.</div></div>
    <div class="faq-item"><div class="faq-question" onclick="this.parentElement.classList.toggle('open')"><span>When will full access be available?</span><span class="faq-toggle">&#x25BC;</span></div><div class="faq-answer">We're launching early access soon. Join the waitlist to get priority access and lock in launch pricing. Waitlist members receive 60 days free.</div></div>
  </div>
</section>
${FOOTER}
<script>
function handleWaitlist(e){e.preventDefault();e.target.querySelector('input').value='';document.getElementById('waitlistSuccess').style.display='block';setTimeout(()=>{document.getElementById('waitlistSuccess').style.display='none'},5000)}
function pricingClick(el){el.disabled=true;el.style.opacity='.7';el.style.cursor='default';el.innerHTML='<span style="display:inline-flex;align-items:center;gap:.5rem"><svg width="16" height="16" viewBox="0 0 16 16" fill="none" style="animation:spin 1s linear infinite"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="2" stroke-dasharray="28" stroke-dashoffset="10"/></svg>Loading\u2026</span>';}
</script>
<style>@keyframes spin{to{transform:rotate(360deg)}}</style>
<script>navigator.sendBeacon("/api/_ping");</script>
</body></html>`);
});

// ─── Scrubber Page ─────────────────────────────────────────────────────────────
app.get("/scrubber", async (c) => {
  const user = await getCurrentUser(c);
  const accessLevel = await getUserAccessLevel(c.env.DB, user?.user_id ?? null);

  // Fetch PM connections and plan info
  let pmConnections: Record<string, boolean> = {};
  let canConnectPm = false;
  let isPro = false;
  if (user) {
    canConnectPm = await userCanConnectPm(c.env.DB, user.user_id);
    const conns = await c.env.DB.prepare("SELECT system FROM pm_connections WHERE user_id = ?")
      .bind(user.user_id).all<{ system: string }>();
    for (const row of conns.results || []) pmConnections[row.system] = true;
    const planRow = await c.env.DB.prepare("SELECT plan FROM users WHERE id = ?").bind(user.user_id).first<{ plan: string }>();
    const p = (planRow?.plan || "").toLowerCase();
    isPro = p === "professional" || p === "pro";
  }
  const drchronoConfigured = !!(c.env.DRCHRONO_CLIENT_ID && c.env.DRCHRONO_CLIENT_SECRET);

  // Check for PM redirect messages
  const url = new URL(c.req.url);
  const pmConnected = url.searchParams.get("pm_connected");
  const pmError = url.searchParams.get("pm_error");

  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AI Claim Scrubber &#x2014; ClinicOS AI</title>
<style>
${SHARED_STYLES}
body{background:#f1f5f9}
.scrubber-hero{background:linear-gradient(135deg,var(--navy) 0%,#0d2144 100%);color:#fff;padding:3.5rem 2rem 4rem;text-align:center;position:relative;overflow:hidden}
.scrubber-hero::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 70% 50%,rgba(6,182,212,.15) 0%,transparent 60%);pointer-events:none}
.scrubber-hero .badge-free{display:inline-block;background:rgba(16,185,129,.2);border:1px solid rgba(16,185,129,.4);color:#6ee7b7;border-radius:20px;padding:.25rem .9rem;font-size:.8rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:1rem}
.scrubber-hero h1{font-size:2.75rem;font-weight:800;margin-bottom:.75rem;letter-spacing:-.5px;position:relative}
.scrubber-hero p{color:rgba(255,255,255,.8);font-size:1.1rem;max-width:580px;margin:0 auto;position:relative}
.scrubber-body{max-width:920px;margin:0 auto;padding:2.5rem 1.5rem 4rem}
.card{background:#fff;border-radius:16px;border:1px solid #e2e8f0;padding:2rem;margin-bottom:1.5rem;box-shadow:0 4px 16px rgba(0,0,0,.05)}
.upload-zone{border:2.5px dashed #cbd5e1;border-radius:12px;padding:3rem 2rem;text-align:center;cursor:pointer;transition:all .25s ease;background:#fafcff;position:relative}
.upload-zone:hover,.upload-zone.dragover{border-color:var(--electric-blue);background:#f0f9ff}
.upload-zone.dragover{box-shadow:0 0 0 4px rgba(2,132,199,.12)}
.upload-icon{font-size:2.5rem;margin-bottom:1rem;display:block}
.upload-zone h3{font-size:1.15rem;color:var(--navy);font-weight:700;margin-bottom:.4rem}
.upload-zone p{color:var(--gray-dark);font-size:.9rem}
.upload-zone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.upload-meta{display:flex;justify-content:space-between;align-items:center;margin-top:1.25rem;font-size:.85rem;color:var(--gray-dark);flex-wrap:wrap;gap:.5rem}
.sample-link{color:var(--electric-blue);font-weight:600;text-decoration:none;display:inline-flex;align-items:center;gap:.3rem;transition:opacity .2s}
.sample-link:hover{opacity:.8;text-decoration:underline}
.file-selected{display:none;background:#f0f9ff;border:2px solid var(--electric-blue);border-radius:10px;padding:1rem 1.25rem;align-items:center;gap:1rem;margin-top:1rem}
.file-selected.visible{display:flex}
.file-icon{font-size:1.5rem}
.file-info{flex:1}
.file-name{font-weight:600;color:var(--navy);font-size:.95rem}
.file-size{color:var(--gray-dark);font-size:.8rem;margin-top:.1rem}
.btn-analyze{width:100%;margin-top:1.25rem;padding:1rem;background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));color:#fff;border:none;border-radius:10px;font-size:1rem;font-weight:700;cursor:pointer;transition:all .25s ease;display:flex;align-items:center;justify-content:center;gap:.5rem;letter-spacing:.2px}
.btn-analyze:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 12px 28px rgba(2,132,199,.35)}
.btn-analyze:disabled{opacity:.55;cursor:not-allowed;transform:none}
.loading-state{display:none;text-align:center;padding:2.5rem}
.loading-state.visible{display:block}
.spinner{width:48px;height:48px;border:4px solid #e2e8f0;border-top-color:var(--electric-blue);border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 1.25rem}
@keyframes spin{to{transform:rotate(360deg)}}
.loading-state h3{color:var(--navy);font-size:1.1rem;font-weight:700;margin-bottom:.4rem}
.loading-state p{color:var(--gray-dark);font-size:.9rem}
.loading-dots::after{content:'...';animation:ldots 1.5s steps(4,end) infinite}
@keyframes ldots{0%,20%{content:'.'}40%{content:'..'}60%,100%{content:'...'}}
.error-banner{display:none;background:#fef2f2;border:1.5px solid #fca5a5;border-radius:10px;padding:1rem 1.25rem;color:#dc2626;font-size:.92rem;align-items:flex-start;gap:.75rem;margin-top:1rem}
.error-banner.visible{display:flex}
.results-section{display:none}
.results-section.visible{display:block}
.summary-bar{background:linear-gradient(135deg,var(--navy),#0d2144);color:#fff;border-radius:14px;padding:1.4rem 1.75rem;display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem;box-shadow:0 4px 20px rgba(15,23,42,.25)}
.summary-stats{display:flex;gap:2rem;flex-wrap:wrap}
.summary-stat{text-align:center;min-width:48px}
.summary-stat .num{font-size:1.9rem;font-weight:800;line-height:1}
.summary-stat .lbl{font-size:.7rem;color:rgba(255,255,255,.6);text-transform:uppercase;letter-spacing:.5px;margin-top:.2rem}
.num-red{color:#f87171}
.num-amber{color:#fbbf24}
.num-blue{color:#60a5fa}
.num-green{color:#34d399}
.sep{width:1px;background:rgba(255,255,255,.15);align-self:stretch;margin:0 .5rem}
.btn-download{background:#fff;color:var(--navy);border:none;border-radius:8px;padding:.7rem 1.3rem;font-size:.88rem;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:.4rem;transition:all .2s ease;white-space:nowrap}
.btn-download:hover{background:#f0f9ff;transform:translateY(-1px)}
.table-wrap{overflow-x:auto;border-radius:12px;border:1px solid #e2e8f0}
table{width:100%;border-collapse:collapse;font-size:.875rem}
thead{background:var(--navy)}
thead th{padding:.85rem 1rem;text-align:left;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px;white-space:nowrap}
tbody tr{border-bottom:1px solid #f1f5f9;transition:background .15s ease}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:#f8fafc}
tbody td{padding:.9rem 1rem;color:#334155;vertical-align:top;line-height:1.5}
.sev-badge{display:inline-flex;align-items:center;gap:.3rem;padding:.25rem .65rem;border-radius:20px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap}
.sev-High{background:#fef2f2;color:#dc2626;border:1px solid #fecaca}
.sev-Medium{background:#fffbeb;color:#b45309;border:1px solid #fde68a}
.sev-Low{background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe}
.sev-dot{width:6px;height:6px;border-radius:50%;background:currentColor;display:inline-block;flex-shrink:0}
.issue-type-tag{font-weight:600;color:var(--navy);font-size:.78rem;background:#f1f5f9;display:inline-block;padding:.15rem .5rem;border-radius:4px;margin-bottom:.35rem;border:1px solid #e2e8f0}
.issue-desc{color:#475569;font-size:.84rem;line-height:1.55}
.fix-text{color:#0369a1;font-size:.82rem;font-style:italic;margin-top:.3rem;line-height:1.5}
.no-issues{text-align:center;padding:2.5rem;color:var(--gray-dark)}
.custom-rule-badge{display:inline-flex;align-items:center;gap:.3rem;background:#f3e8ff;color:#7c3aed;border:1px solid #c4b5fd;padding:.2rem .6rem;border-radius:20px;font-size:.72rem;font-weight:700;letter-spacing:.3px;white-space:nowrap}
.no-issues .big-check{font-size:3rem;display:block;margin-bottom:.75rem}
.clean-panel{background:#f0fdf4;border:1.5px solid #bbf7d0;border-radius:12px;padding:1.1rem 1.5rem;display:none;align-items:center;justify-content:space-between;gap:.75rem;cursor:pointer;user-select:none;margin-top:1.25rem}
.clean-panel.visible{display:flex}
.clean-panel-info{display:flex;align-items:center;gap:.75rem}
.clean-icon{font-size:1.4rem}
.clean-title{color:#166534;font-weight:700;font-size:.95rem}
.clean-sub{color:#15803d;font-size:.82rem}
.clean-toggle{color:#166534;font-weight:700;font-size:.82rem}
.clean-list-wrap{display:none;margin-top:.75rem;border-top:1px solid #bbf7d0;padding-top:.75rem}
.clean-list-wrap.open{display:block}
.clean-tbl{width:100%;font-size:.8rem;color:#475569;border-collapse:collapse}
.clean-tbl td{padding:.3rem .5rem}
.clean-tbl tr:nth-child(even){background:#f7fef9}
.btn-new{width:100%;margin-top:1.25rem;padding:.85rem;background:transparent;color:var(--electric-blue);border:2px solid var(--electric-blue);border-radius:10px;font-size:.95rem;font-weight:700;cursor:pointer;transition:all .2s ease}
.btn-new:hover{background:#f0f9ff}
@media(max-width:640px){.summary-bar{flex-direction:column;text-align:center}.summary-stats{gap:1rem;justify-content:center}.scrubber-hero h1{font-size:1.85rem}.sep{display:none}}
.batch-toggle-row{display:flex;align-items:center;gap:.75rem;padding:1rem 1.25rem;background:#f8faff;border:1.5px solid #e2e8f0;border-radius:12px;margin-bottom:1.25rem}
.batch-toggle-row.pro-only-locked{cursor:pointer}
.toggle-switch{position:relative;display:inline-block;width:44px;height:24px;flex-shrink:0}
.toggle-switch input{opacity:0;width:0;height:0}
.toggle-slider{position:absolute;inset:0;background:#cbd5e1;border-radius:24px;transition:.25s;cursor:pointer}
.toggle-slider:before{content:'';position:absolute;left:3px;top:3px;width:18px;height:18px;border-radius:50%;background:#fff;transition:.25s;box-shadow:0 1px 3px rgba(0,0,0,.2)}
.toggle-switch input:checked + .toggle-slider{background:var(--electric-blue)}
.toggle-switch input:checked + .toggle-slider:before{transform:translateX(20px)}
.toggle-switch input:disabled + .toggle-slider{opacity:.6;cursor:not-allowed}
.batch-toggle-label{flex:1}
.batch-toggle-label strong{display:block;color:var(--navy);font-size:.95rem;font-weight:700}
.batch-toggle-label span{color:#64748b;font-size:.82rem}
.batch-pro-badge{background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;font-size:.7rem;font-weight:700;padding:.15rem .5rem;border-radius:20px;text-transform:uppercase;letter-spacing:.4px;flex-shrink:0}
.batch-upgrade-tip{display:none;font-size:.82rem;color:#7c3aed;background:#faf5ff;border:1px solid #c4b5fd;border-radius:6px;padding:.4rem .75rem;margin-top:.4rem}
.batch-upload-zone{border:2.5px dashed #cbd5e1;border-radius:12px;padding:2.5rem 2rem;text-align:center;cursor:pointer;transition:all .25s ease;background:#fafcff;position:relative}
.batch-upload-zone:hover,.batch-upload-zone.dragover{border-color:var(--electric-blue);background:#f0f9ff}
.batch-upload-zone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.batch-queue{margin-top:1.25rem;display:flex;flex-direction:column;gap:.5rem}
.batch-file-row{display:flex;align-items:center;gap:.75rem;padding:.65rem 1rem;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;font-size:.88rem}
.batch-file-row .bfr-name{flex:1;font-weight:600;color:var(--navy);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.batch-file-row .bfr-size{color:#64748b;font-size:.8rem;white-space:nowrap}
.batch-status{display:inline-flex;align-items:center;gap:.3rem;padding:.2rem .6rem;border-radius:20px;font-size:.72rem;font-weight:700;text-transform:uppercase;white-space:nowrap}
.bs-queued{background:#f1f5f9;color:#475569;border:1px solid #e2e8f0}
.bs-processing{background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe}
.bs-done{background:#f0fdf4;color:#166534;border:1px solid #bbf7d0}
.bs-error{background:#fef2f2;color:#dc2626;border:1px solid #fecaca}
.batch-spinner{width:10px;height:10px;border:2px solid #bfdbfe;border-top-color:#1d4ed8;border-radius:50%;animation:spin .8s linear infinite;display:inline-block}
.batch-progress-bar{background:#e2e8f0;border-radius:8px;height:6px;overflow:hidden;margin-bottom:.75rem}
.batch-progress-fill{height:100%;background:linear-gradient(90deg,var(--electric-blue),var(--electric-teal));border-radius:8px;transition:width .4s ease}
.btn-start-batch{width:100%;margin-top:1.25rem;padding:1rem;background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));color:#fff;border:none;border-radius:10px;font-size:1rem;font-weight:700;cursor:pointer;transition:all .25s ease;display:flex;align-items:center;justify-content:center;gap:.5rem}
.btn-start-batch:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 12px 28px rgba(2,132,199,.35)}
.btn-start-batch:disabled{opacity:.55;cursor:not-allowed;transform:none}
.btn-remove-file{background:none;border:none;color:#94a3b8;cursor:pointer;font-size:1rem;padding:.1rem .3rem;border-radius:4px;transition:color .15s,background .15s;flex-shrink:0}
.btn-remove-file:hover{color:#dc2626;background:#fef2f2}
</style>
</head>
<body>
${buildNav(user)}
<div class="scrubber-hero">
  <div class="badge-free">${accessLevel === 'paid' ? '&#x2713; Unlimited Access' : accessLevel === 'trial_active' ? '&#x2713; Free Trial &#x2022; Full Access' : accessLevel === 'trial_expired' ? '&#x26A0; Trial Ended' : 'Free &#x2022; Preview First 3 Results'}</div>
  <h1>AI Claim Scrubber</h1>
  <p>Upload your claims CSV and get an instant error report with severity ratings and suggested fixes.</p>
</div>
${accessLevel === 'trial_expired' ? `
<div style="max-width:920px;margin:2rem auto 0;padding:0 1.5rem">
  <div style="background:#fef2f2;border:2px solid #fca5a5;border-radius:14px;padding:2rem;text-align:center">
    <div style="font-size:2.5rem;margin-bottom:.75rem">&#x23F0;</div>
    <h2 style="color:#991b1b;font-size:1.35rem;font-weight:800;margin-bottom:.6rem">Your free trial has ended</h2>
    <p style="color:#7f1d1d;font-size:.97rem;max-width:480px;margin:0 auto 1.5rem">Upgrade to a paid plan to continue running AI claim analyses, saving reports, and catching denial risks before submission.</p>
    <a href="/#pricing" class="btn btn-primary" style="display:inline-block;padding:.85rem 2rem;font-size:1rem;font-weight:700;background:linear-gradient(135deg,#dc2626,#b91c1c);border:none;border-radius:10px;color:#fff;text-decoration:none">View Plans &#x2192;</a>
    <p style="margin-top:1rem;font-size:.85rem;color:#9ca3af">Questions? <a href="mailto:support@clinicosal.launchyard.app" style="color:#dc2626">Contact support</a></p>
  </div>
</div>` : ''}
<div class="scrubber-body">
  <div style="background:#fffbeb;border:1.5px solid #f59e0b;border-radius:10px;padding:1.25rem 1.5rem;margin-bottom:2rem">
    <div style="display:flex;align-items:flex-start;gap:.75rem">
      <span style="font-size:1.4rem;line-height:1;flex-shrink:0">&#x26A0;&#xFE0F;</span>
      <div>
        <p style="font-weight:700;color:#92400e;margin:0 0 .4rem;font-size:1rem">Please de-identify your CSV before uploading</p>
        <p style="color:#78350f;margin:0 0 .75rem;font-size:.93rem">ClinicOS AI is currently a <strong>pilot tool</strong>. Until full HIPAA-compliant processing is available, please remove or mask any protected health information (PHI) from your file before uploading.</p>
        <p style="color:#78350f;margin:0 0 .75rem;font-size:.93rem">Specifically: replace patient names with IDs (e.g. <code style="background:#fef3c7;padding:.1rem .3rem;border-radius:3px">Patient_001</code>), remove or mask dates of birth, and redact full Social Security Numbers.</p>
        <details style="margin-top:.5rem">
          <summary style="cursor:pointer;font-weight:600;color:#92400e;font-size:.93rem;user-select:none">&#x25B6; How to de-identify your CSV (click to expand)</summary>
          <ul style="margin:.75rem 0 0 1rem;padding:0;color:#78350f;font-size:.9rem;line-height:1.8">
            <li>Open your CSV in Excel or Google Sheets.</li>
            <li>Find any column containing patient names and replace each name with a sequential ID like <strong>Patient_001</strong>, <strong>Patient_002</strong>, etc.</li>
            <li>Delete or blank out any column containing dates of birth (e.g. "DOB", "Date of Birth").</li>
            <li>Find any SSN or Social Security Number column and either delete the column or replace values with <strong>XXX-XX-XXXX</strong>.</li>
            <li>Remove any other columns with personal contact details (phone numbers, home addresses, personal email addresses) that aren't needed for claim scrubbing.</li>
          </ul>
        </details>
        <p style="margin:.75rem 0 0;font-size:.87rem;color:#92400e;font-style:italic">Full HIPAA-compliant processing is coming soon. For now, please de-identify your data before uploading.</p>
      </div>
    </div>
  </div>
  <div class="card" id="uploadCard" ${accessLevel === 'trial_expired' ? 'style="display:none"' : ''}>
    <div style="margin-bottom:1.5rem">
      <label for="payerSelect" style="display:block;font-weight:700;color:var(--navy);font-size:.95rem;margin-bottom:.5rem">&#x1F3E5; Select Payer</label>
      <select id="payerSelect" style="width:100%;padding:.75rem 1rem;border:1.5px solid #cbd5e1;border-radius:10px;font-size:.95rem;color:var(--navy);background:#fff;cursor:pointer;transition:border-color .2s ease;appearance:none;background-image:url('data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%2212%22 height=%2212%22 viewBox=%220 0 12 12%22><path fill=%22%23334155%22 d=%22M6 8L1 3h10z%22/></svg>');background-repeat:no-repeat;background-position:right 1rem center;padding-right:2.5rem" onchange="onPayerChange()">
        <option value="general">Other / General (default)</option>
        <option value="medicare">Medicare</option>
        <option value="medicaid">Medicaid</option>
        <option value="bcbs">Blue Cross Blue Shield</option>
        <option value="uhc">United Healthcare</option>
        <option value="aetna">Aetna</option>
        <option value="cigna">Cigna</option>
        <option value="humana">Humana</option>
      </select>
      <p style="margin-top:.5rem;font-size:.82rem;color:#64748b">Select your payer for enhanced rule validation. General rules apply to all payers as a baseline.</p>
      ${accessLevel !== 'paid' ? `<div id="payerProBanner" style="display:none;margin-top:.75rem;background:#faf5ff;border:1.5px solid #c4b5fd;border-radius:8px;padding:.75rem 1rem;font-size:.85rem;color:#6d28d9">&#x2728; <strong>Professional plan feature:</strong> Payer-specific rules (Medicare MUEs, UHC modifier guidance, BCBS bundling, and more) are available on the <a href="/#pricing" style="color:#7c3aed;font-weight:700">Professional plan</a>. Your claims will be analyzed with general rules.</div>` : ''}
    </div>

    ${user ? `
    <!-- Batch Mode Toggle -->
    <div class="batch-toggle-row${!isPro ? ' pro-only-locked' : ''}" id="batchToggleRow" onclick="${!isPro ? 'showBatchUpgradeTip()' : ''}">
      <label class="toggle-switch" onclick="event.stopPropagation()">
        <input type="checkbox" id="batchToggleInput" ${!isPro ? 'disabled' : ''} onchange="onBatchToggleChange(this.checked)">
        <span class="toggle-slider"></span>
      </label>
      <div class="batch-toggle-label">
        <strong>Batch Mode</strong>
        <span>Process up to 10 CSV files at once</span>
        <div class="batch-upgrade-tip" id="batchUpgradeTip">&#x1F512; Batch Mode is a Professional feature &mdash; <a href="/#pricing" style="color:#7c3aed;font-weight:700">upgrade to process multiple files at once</a></div>
      </div>
      <span class="batch-pro-badge">Pro</span>
    </div>` : ''}

    <!-- Single file upload (shown by default) -->
    <div id="singleUploadSection">
      ${isReadOnly(user) ? `<div style="background:#fef3c7;border:1.5px solid #f59e0b;border-radius:10px;padding:1.25rem 1.5rem;color:#92400e;font-size:.95rem;margin-bottom:.5rem">&#x1F441;&#xFE0F; <strong>View only</strong> — You have read-only access. Contact your Admin to request upload permissions.</div>` : ''}
      <div class="upload-zone" id="dropZone" ${isReadOnly(user) ? 'style="opacity:.5;pointer-events:none"' : ''}>
        <input type="file" id="fileInput" accept=".csv" ${isReadOnly(user) ? 'disabled' : ''} />
        <span class="upload-icon">&#x1F4C2;</span>
        <h3>Drag &amp; drop your claims CSV here</h3>
        <p>or click to browse &mdash; CSV files only, up to 5MB</p>
      </div>
      <div class="upload-meta">
        <span>Analyzes up to 100 claims per upload.</span>
        <a href="/sample-claims.csv" download class="sample-link">&#x2B07; Download Sample CSV</a>
      </div>
      ${user && accessLevel !== 'trial_expired' ? '<p style="margin-top:.75rem;font-size:.85rem;color:#0369a1;background:#f0f9ff;border:1px solid #bae6fd;border-radius:8px;padding:.5rem .85rem;display:inline-block">&#x1F4BE; Saving to your account</p>' : ''}
    </div>

    <!-- Batch upload section (shown when batch mode is on) -->
    <div id="batchUploadSection" style="display:none">
      <div class="batch-upload-zone" id="batchDropZone">
        <input type="file" id="batchFileInput" accept=".csv" multiple />
        <span class="upload-icon">&#x1F4C2;</span>
        <h3>Drag &amp; drop up to 10 CSV files here</h3>
        <p>or click to select multiple files &mdash; CSV only, up to 5MB each</p>
      </div>
      <div id="batchQueueWrap" style="display:none;margin-top:1.25rem">
        <div id="batchProgressWrap" style="display:none;margin-bottom:.75rem">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.4rem">
            <span id="batchProgressLabel" style="font-size:.88rem;font-weight:600;color:var(--navy)">Processing file 1 of 1...</span>
            <span id="batchProgressPct" style="font-size:.82rem;color:#64748b">0%</span>
          </div>
          <div class="batch-progress-bar"><div class="batch-progress-fill" id="batchProgressFill" style="width:0%"></div></div>
        </div>
        <div class="batch-queue" id="batchQueue"></div>
        <button class="btn-start-batch" id="startBatchBtn" disabled onclick="startBatch()">
          &#x26A1; Start Batch Processing
        </button>
      </div>
    </div>
    <div class="file-selected" id="fileSelected">
      <div class="file-icon">&#x1F4C4;</div>
      <div class="file-info">
        <div class="file-name" id="fileName">&#x2014;</div>
        <div class="file-size" id="fileSize">&#x2014;</div>
      </div>
    </div>
    <div class="error-banner" id="errorBanner">
      <span>&#x26A0;&#xFE0F;</span>
      <div id="errorMsg">Something went wrong.</div>
    </div>
    <button class="btn-analyze" id="analyzeBtn" disabled onclick="analyzeClaims()">
      &#x26A1; Analyze Claims
    </button>
  </div>

  ${accessLevel !== 'trial_expired' ? `
  <!-- PM Connect section -->
  <div class="card" id="pmConnectSection" style="margin-bottom:1.5rem">
    <div style="margin-bottom:1.25rem">
      <div style="display:flex;align-items:center;gap:.6rem;margin-bottom:.35rem">
        <span style="font-size:1.3rem">&#x1F517;</span>
        <h2 style="font-size:1.1rem;font-weight:800;color:#0f172a">Or import directly from your practice management system</h2>
      </div>
      <p style="color:#64748b;font-size:.88rem">Skip the CSV export — connect your PM system and fetch recent claims directly for AI scrubbing.</p>
    </div>
    ${pmConnected === 'drchrono' ? '<div style="background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:.75rem 1rem;margin-bottom:1rem;color:#166534;font-size:.9rem;font-weight:600">&#x2705; DrChrono connected successfully!</div>' : ''}
    ${pmError === 'upgrade' ? '<div style="background:#fef3c7;border:1px solid #f59e0b;border-radius:8px;padding:.75rem 1rem;margin-bottom:1rem;color:#92400e;font-size:.9rem">&#x26A0;&#xFE0F; Upgrade to Growth or Professional to connect PM systems.</div>' : ''}
    ${pmError === 'drchrono_not_configured' ? '<div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:.75rem 1rem;margin-bottom:1rem;color:#dc2626;font-size:.9rem">DrChrono OAuth is not yet configured. Please contact support.</div>' : ''}
    ${pmError === 'drchrono_token_failed' ? '<div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:.75rem 1rem;margin-bottom:1rem;color:#dc2626;font-size:.9rem">DrChrono authorization failed. Please try again.</div>' : ''}
    ${pmError === 'drchrono_denied' ? '<div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:.75rem 1rem;margin-bottom:1rem;color:#dc2626;font-size:.9rem">DrChrono authorization was denied. Please try again.</div>' : ''}
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1rem">

      <!-- Kareo / Tebra card -->
      <div style="border:1.5px solid ${pmConnections['kareo'] ? '#86efac' : '#e2e8f0'};border-radius:12px;padding:1.25rem;background:${pmConnections['kareo'] ? '#f0fdf4' : '#fff'}">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.75rem">
          <div style="display:flex;align-items:center;gap:.6rem">
            <div style="width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,#3b82f6,#1d4ed8);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:.85rem">K</div>
            <div><div style="font-weight:700;color:#0f172a;font-size:.95rem">Kareo / Tebra</div><div style="color:#64748b;font-size:.75rem">SOAP API</div></div>
          </div>
          ${pmConnections['kareo'] ? '<span style="display:inline-flex;align-items:center;gap:.3rem;background:#dcfce7;color:#166534;border:1px solid #86efac;border-radius:20px;padding:.2rem .7rem;font-size:.72rem;font-weight:700">&#x2713; Connected</span>' : ''}
        </div>
        ${pmConnections['kareo'] ? `
          <div style="margin-bottom:.75rem">
            <label style="display:block;font-size:.8rem;font-weight:600;color:#475569;margin-bottom:.4rem">Date Range</label>
            <select id="kareoDays" style="width:100%;padding:.5rem .75rem;border:1.5px solid #cbd5e1;border-radius:8px;font-size:.88rem;color:#0f172a;background:#fff;cursor:pointer">
              <option value="7">Last 7 days</option>
              <option value="14">Last 14 days</option>
              <option value="30">Last 30 days</option>
            </select>
          </div>
          <button onclick="pmFetchClaims('kareo','kareoDays')" style="width:100%;padding:.6rem;background:linear-gradient(135deg,#3b82f6,#1d4ed8);color:#fff;border:none;border-radius:8px;font-weight:700;font-size:.88rem;cursor:pointer;transition:opacity .2s" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">&#x2B07; Fetch Recent Claims</button>
        ` : canConnectPm ? `
          <p style="color:#64748b;font-size:.83rem;margin-bottom:.75rem">Enter your Kareo/Tebra API credentials from Settings &gt; API.</p>
          <button onclick="showPmModal('kareo')" style="width:100%;padding:.6rem;background:linear-gradient(135deg,#3b82f6,#1d4ed8);color:#fff;border:none;border-radius:8px;font-weight:700;font-size:.88rem;cursor:pointer;transition:opacity .2s" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">Connect Kareo</button>
        ` : `
          <p style="color:#94a3b8;font-size:.83rem;margin-bottom:.75rem">Connect your Kareo/Tebra PM system to import claims directly.</p>
          <button disabled title="${user ? 'Upgrade to Growth or Professional to connect PM systems' : 'Sign up to connect PM systems'}" style="width:100%;padding:.6rem;background:#e2e8f0;color:#94a3b8;border:none;border-radius:8px;font-weight:700;font-size:.88rem;cursor:not-allowed">${user ? '&#x1F512; Upgrade to Connect' : '&#x1F512; Sign Up to Connect'}</button>
          ${!user ? '<p style="margin-top:.5rem;font-size:.78rem;text-align:center"><a href="/signup" style="color:#0284c7;font-weight:600">Start free trial</a> or <a href="/login" style="color:#0284c7;font-weight:600">sign in</a></p>' : '<p style="margin-top:.5rem;font-size:.78rem;text-align:center;color:#64748b"><a href="/#pricing" style="color:#7c3aed;font-weight:600">Upgrade to Growth &#x2192;</a></p>'}
        `}
      </div>

      <!-- AdvancedMD card -->
      <div style="border:1.5px solid ${pmConnections['advancedmd'] ? '#86efac' : '#e2e8f0'};border-radius:12px;padding:1.25rem;background:${pmConnections['advancedmd'] ? '#f0fdf4' : '#fff'}">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.75rem">
          <div style="display:flex;align-items:center;gap:.6rem">
            <div style="width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,#10b981,#059669);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:.75rem">AMD</div>
            <div><div style="font-weight:700;color:#0f172a;font-size:.95rem">AdvancedMD</div><div style="color:#64748b;font-size:.75rem">REST API</div></div>
          </div>
          ${pmConnections['advancedmd'] ? '<span style="display:inline-flex;align-items:center;gap:.3rem;background:#dcfce7;color:#166534;border:1px solid #86efac;border-radius:20px;padding:.2rem .7rem;font-size:.72rem;font-weight:700">&#x2713; Connected</span>' : ''}
        </div>
        ${pmConnections['advancedmd'] ? `
          <div style="margin-bottom:.75rem">
            <label style="display:block;font-size:.8rem;font-weight:600;color:#475569;margin-bottom:.4rem">Date Range</label>
            <select id="amdDays" style="width:100%;padding:.5rem .75rem;border:1.5px solid #cbd5e1;border-radius:8px;font-size:.88rem;color:#0f172a;background:#fff;cursor:pointer">
              <option value="7">Last 7 days</option>
              <option value="14">Last 14 days</option>
              <option value="30">Last 30 days</option>
            </select>
          </div>
          <button onclick="pmFetchClaims('advancedmd','amdDays')" style="width:100%;padding:.6rem;background:linear-gradient(135deg,#10b981,#059669);color:#fff;border:none;border-radius:8px;font-weight:700;font-size:.88rem;cursor:pointer;transition:opacity .2s" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">&#x2B07; Fetch Recent Claims</button>
        ` : canConnectPm ? `
          <p style="color:#64748b;font-size:.83rem;margin-bottom:.75rem">Enter your AdvancedMD credentials from Administration &gt; API.</p>
          <button onclick="showPmModal('advancedmd')" style="width:100%;padding:.6rem;background:linear-gradient(135deg,#10b981,#059669);color:#fff;border:none;border-radius:8px;font-weight:700;font-size:.88rem;cursor:pointer;transition:opacity .2s" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">Connect AdvancedMD</button>
        ` : `
          <p style="color:#94a3b8;font-size:.83rem;margin-bottom:.75rem">Connect your AdvancedMD system to import claims directly.</p>
          <button disabled title="${user ? 'Upgrade to Growth or Professional to connect PM systems' : 'Sign up to connect PM systems'}" style="width:100%;padding:.6rem;background:#e2e8f0;color:#94a3b8;border:none;border-radius:8px;font-weight:700;font-size:.88rem;cursor:not-allowed">${user ? '&#x1F512; Upgrade to Connect' : '&#x1F512; Sign Up to Connect'}</button>
          ${!user ? '<p style="margin-top:.5rem;font-size:.78rem;text-align:center"><a href="/signup" style="color:#0284c7;font-weight:600">Start free trial</a> or <a href="/login" style="color:#0284c7;font-weight:600">sign in</a></p>' : '<p style="margin-top:.5rem;font-size:.78rem;text-align:center;color:#64748b"><a href="/#pricing" style="color:#7c3aed;font-weight:600">Upgrade to Growth &#x2192;</a></p>'}
        `}
      </div>

      <!-- DrChrono card -->
      <div style="border:1.5px solid ${pmConnections['drchrono'] ? '#86efac' : '#e2e8f0'};border-radius:12px;padding:1.25rem;background:${pmConnections['drchrono'] ? '#f0fdf4' : '#fff'}">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.75rem">
          <div style="display:flex;align-items:center;gap:.6rem">
            <div style="width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,#8b5cf6,#7c3aed);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:.75rem">DC</div>
            <div><div style="font-weight:700;color:#0f172a;font-size:.95rem">DrChrono</div><div style="color:#64748b;font-size:.75rem">OAuth 2.0</div></div>
          </div>
          ${pmConnections['drchrono'] ? '<span style="display:inline-flex;align-items:center;gap:.3rem;background:#dcfce7;color:#166534;border:1px solid #86efac;border-radius:20px;padding:.2rem .7rem;font-size:.72rem;font-weight:700">&#x2713; Connected</span>' : ''}
        </div>
        ${pmConnections['drchrono'] ? `
          <div style="margin-bottom:.75rem">
            <label style="display:block;font-size:.8rem;font-weight:600;color:#475569;margin-bottom:.4rem">Date Range</label>
            <select id="drchronoDays" style="width:100%;padding:.5rem .75rem;border:1.5px solid #cbd5e1;border-radius:8px;font-size:.88rem;color:#0f172a;background:#fff;cursor:pointer">
              <option value="7">Last 7 days</option>
              <option value="14">Last 14 days</option>
              <option value="30">Last 30 days</option>
            </select>
          </div>
          <button onclick="pmFetchClaims('drchrono','drchronoDays')" style="width:100%;padding:.6rem;background:linear-gradient(135deg,#8b5cf6,#7c3aed);color:#fff;border:none;border-radius:8px;font-weight:700;font-size:.88rem;cursor:pointer;transition:opacity .2s" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">&#x2B07; Fetch Recent Claims</button>
        ` : !drchronoConfigured ? `
          <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:.75rem;margin-bottom:.5rem">
            <p style="color:#64748b;font-size:.82rem;font-weight:600;margin-bottom:.2rem">&#x1F6A7; Coming Soon — OAuth setup required</p>
            <p style="color:#94a3b8;font-size:.78rem">DrChrono OAuth setup in progress — contact support to enable.</p>
          </div>
        ` : canConnectPm ? `
          <p style="color:#64748b;font-size:.83rem;margin-bottom:.75rem">Click below to authorize ClinicOS AI to read your DrChrono billing data.</p>
          <a href="/api/pm/drchrono/connect" style="display:block;width:100%;padding:.6rem;background:linear-gradient(135deg,#8b5cf6,#7c3aed);color:#fff;border:none;border-radius:8px;font-weight:700;font-size:.88rem;cursor:pointer;text-align:center;text-decoration:none;transition:opacity .2s" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">Connect DrChrono</a>
        ` : `
          <p style="color:#94a3b8;font-size:.83rem;margin-bottom:.75rem">Connect your DrChrono account to import claims via OAuth.</p>
          <button disabled title="${user ? 'Upgrade to Growth or Professional to connect PM systems' : 'Sign up to connect PM systems'}" style="width:100%;padding:.6rem;background:#e2e8f0;color:#94a3b8;border:none;border-radius:8px;font-weight:700;font-size:.88rem;cursor:not-allowed">${user ? '&#x1F512; Upgrade to Connect' : '&#x1F512; Sign Up to Connect'}</button>
          ${!user ? '<p style="margin-top:.5rem;font-size:.78rem;text-align:center"><a href="/signup" style="color:#0284c7;font-weight:600">Start free trial</a> or <a href="/login" style="color:#0284c7;font-weight:600">sign in</a></p>' : '<p style="margin-top:.5rem;font-size:.78rem;text-align:center;color:#64748b"><a href="/#pricing" style="color:#7c3aed;font-weight:600">Upgrade to Growth &#x2192;</a></p>'}
        `}
      </div>

    </div>
    <!-- PM loading + error state -->
    <div id="pmLoadingState" style="display:none;text-align:center;padding:1.5rem;margin-top:1rem">
      <div class="spinner" style="width:36px;height:36px;margin-bottom:.75rem"></div>
      <p style="color:#0f172a;font-weight:600;font-size:.95rem" id="pmLoadingMsg">Fetching claims...</p>
    </div>
    <div id="pmErrorBanner" style="display:none;background:#fef2f2;border:1.5px solid #fca5a5;border-radius:10px;padding:.85rem 1.1rem;color:#dc2626;font-size:.9rem;margin-top:1rem;align-items:flex-start;gap:.6rem">
      <span>&#x26A0;&#xFE0F;</span>
      <span id="pmErrorMsg"></span>
    </div>
  </div>

  <!-- Kareo modal -->
  <div id="kareoModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:2000;align-items:center;justify-content:center;padding:1rem">
    <div style="background:#fff;border-radius:16px;padding:2rem;width:100%;max-width:440px;box-shadow:0 20px 60px rgba(0,0,0,.25)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem">
        <h3 style="font-weight:800;color:#0f172a;font-size:1.1rem">Connect Kareo / Tebra</h3>
        <button onclick="closeModal('kareoModal')" style="background:none;border:none;cursor:pointer;font-size:1.5rem;color:#64748b;line-height:1">&times;</button>
      </div>
      <p style="color:#64748b;font-size:.87rem;margin-bottom:1.25rem">Find these in your Tebra admin under <strong>Settings &gt; API</strong>.</p>
      <div style="margin-bottom:.85rem">
        <label style="display:block;font-weight:700;color:#374151;font-size:.87rem;margin-bottom:.35rem">Customer Key</label>
        <input id="kareoCustomerKey" type="text" placeholder="Your Customer Key" style="width:100%;padding:.7rem .9rem;border:1.5px solid #cbd5e1;border-radius:8px;font-size:.92rem;color:#0f172a;outline:none;transition:border-color .2s" onfocus="this.style.borderColor='#0284c7'" onblur="this.style.borderColor='#cbd5e1'">
      </div>
      <div style="margin-bottom:1.25rem">
        <label style="display:block;font-weight:700;color:#374151;font-size:.87rem;margin-bottom:.35rem">API Key</label>
        <input id="kareoApiKey" type="password" placeholder="Your API Key" style="width:100%;padding:.7rem .9rem;border:1.5px solid #cbd5e1;border-radius:8px;font-size:.92rem;color:#0f172a;outline:none;transition:border-color .2s" onfocus="this.style.borderColor='#0284c7'" onblur="this.style.borderColor='#cbd5e1'">
      </div>
      <div id="kareoModalError" style="display:none;background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:.6rem .9rem;color:#dc2626;font-size:.87rem;margin-bottom:.85rem"></div>
      <div style="display:flex;gap:.75rem">
        <button onclick="closeModal('kareoModal')" style="flex:1;padding:.7rem;background:#f1f5f9;border:none;border-radius:8px;font-weight:600;cursor:pointer;color:#475569">Cancel</button>
        <button onclick="saveKareo()" id="kareoSaveBtn" style="flex:2;padding:.7rem;background:linear-gradient(135deg,#3b82f6,#1d4ed8);color:#fff;border:none;border-radius:8px;font-weight:700;cursor:pointer;transition:opacity .2s" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">Save &amp; Connect</button>
      </div>
    </div>
  </div>

  <!-- AdvancedMD modal -->
  <div id="advancedmdModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:2000;align-items:center;justify-content:center;padding:1rem">
    <div style="background:#fff;border-radius:16px;padding:2rem;width:100%;max-width:440px;box-shadow:0 20px 60px rgba(0,0,0,.25)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem">
        <h3 style="font-weight:800;color:#0f172a;font-size:1.1rem">Connect AdvancedMD</h3>
        <button onclick="closeModal('advancedmdModal')" style="background:none;border:none;cursor:pointer;font-size:1.5rem;color:#64748b;line-height:1">&times;</button>
      </div>
      <p style="color:#64748b;font-size:.87rem;margin-bottom:1.25rem">Find these in AdvancedMD under <strong>Administration &gt; API</strong>.</p>
      <div style="margin-bottom:.85rem">
        <label style="display:block;font-weight:700;color:#374151;font-size:.87rem;margin-bottom:.35rem">Office Code</label>
        <input id="amdOfficeCode" type="text" placeholder="Office Code" style="width:100%;padding:.7rem .9rem;border:1.5px solid #cbd5e1;border-radius:8px;font-size:.92rem;color:#0f172a;outline:none" onfocus="this.style.borderColor='#10b981'" onblur="this.style.borderColor='#cbd5e1'">
      </div>
      <div style="margin-bottom:.85rem">
        <label style="display:block;font-weight:700;color:#374151;font-size:.87rem;margin-bottom:.35rem">Username</label>
        <input id="amdUsername" type="text" placeholder="Username" style="width:100%;padding:.7rem .9rem;border:1.5px solid #cbd5e1;border-radius:8px;font-size:.92rem;color:#0f172a;outline:none" onfocus="this.style.borderColor='#10b981'" onblur="this.style.borderColor='#cbd5e1'">
      </div>
      <div style="margin-bottom:.85rem">
        <label style="display:block;font-weight:700;color:#374151;font-size:.87rem;margin-bottom:.35rem">Password</label>
        <input id="amdPassword" type="password" placeholder="Password" style="width:100%;padding:.7rem .9rem;border:1.5px solid #cbd5e1;border-radius:8px;font-size:.92rem;color:#0f172a;outline:none" onfocus="this.style.borderColor='#10b981'" onblur="this.style.borderColor='#cbd5e1'">
      </div>
      <div style="margin-bottom:1.25rem">
        <label style="display:block;font-weight:700;color:#374151;font-size:.87rem;margin-bottom:.35rem">App Name</label>
        <input id="amdAppName" type="text" placeholder="App Name" style="width:100%;padding:.7rem .9rem;border:1.5px solid #cbd5e1;border-radius:8px;font-size:.92rem;color:#0f172a;outline:none" onfocus="this.style.borderColor='#10b981'" onblur="this.style.borderColor='#cbd5e1'">
      </div>
      <div id="amdModalError" style="display:none;background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:.6rem .9rem;color:#dc2626;font-size:.87rem;margin-bottom:.85rem"></div>
      <div style="display:flex;gap:.75rem">
        <button onclick="closeModal('advancedmdModal')" style="flex:1;padding:.7rem;background:#f1f5f9;border:none;border-radius:8px;font-weight:600;cursor:pointer;color:#475569">Cancel</button>
        <button onclick="saveAdvancedMD()" id="amdSaveBtn" style="flex:2;padding:.7rem;background:linear-gradient(135deg,#10b981,#059669);color:#fff;border:none;border-radius:8px;font-weight:700;cursor:pointer;transition:opacity .2s" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">Save &amp; Connect</button>
      </div>
    </div>
  </div>
  ` : ''}

  <div class="card loading-state" id="loadingState">
    <div class="spinner"></div>
    <h3>Analyzing claims<span class="loading-dots"></span></h3>
    <p>Our AI is checking for billing errors, missing modifiers, duplicate claims, and denial risks.</p>
  </div>

  <div class="results-section" id="resultsSection">
    <div class="summary-bar">
      <div class="summary-stats">
        <div class="summary-stat"><div class="num" id="statFlagged">0</div><div class="lbl">Flagged</div></div>
        <div class="summary-stat"><div class="num" id="statTotal">0</div><div class="lbl">Total</div></div>
        <div class="sep"></div>
        <div class="summary-stat"><div class="num num-red" id="statHigh">0</div><div class="lbl">High</div></div>
        <div class="summary-stat"><div class="num num-amber" id="statMed">0</div><div class="lbl">Medium</div></div>
        <div class="summary-stat"><div class="num num-blue" id="statLow">0</div><div class="lbl">Low</div></div>
        <div class="sep"></div>
        <div class="summary-stat"><div class="num num-green" id="statClean">0</div><div class="lbl">Clean</div></div>
        <div class="sep"></div>
        <div class="summary-stat" style="min-width:80px"><div class="num" id="statPayer" style="font-size:.9rem;letter-spacing:-.2px">General</div><div class="lbl">Payer</div></div>
      </div>
      <button class="btn-download" id="downloadBtn" onclick="downloadReport()">&#x2B07; Download Report</button>
    </div>
    <div id="payerUpgradeBanner" style="display:none;margin-bottom:1.25rem;background:linear-gradient(135deg,#faf5ff,#ede9fe);border:1.5px solid #c4b5fd;border-radius:12px;padding:1.25rem 1.5rem">
      <div style="display:flex;align-items:flex-start;gap:.75rem;flex-wrap:wrap">
        <span style="font-size:1.5rem;line-height:1">&#x2728;</span>
        <div style="flex:1;min-width:240px">
          <p style="font-weight:700;color:#5b21b6;margin:0 0 .3rem;font-size:.97rem">Payer-specific rules are available on the Professional plan.</p>
          <p style="color:#6d28d9;font-size:.88rem;margin:0 0 .75rem">Your claims were scrubbed using general rules only. Upgrade to Professional to catch Medicare MUEs, UHC modifier issues, BCBS bundling rules, and more.</p>
          <a href="/#pricing" style="display:inline-block;padding:.55rem 1.2rem;background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;border-radius:8px;font-weight:700;font-size:.88rem;text-decoration:none">Upgrade to Professional &#x2192;</a>
        </div>
      </div>
    </div>
    <div class="card" style="padding:0;overflow:hidden">
      <div class="table-wrap">
        <table id="resultsTable">
          <thead><tr>
            <th style="width:48px">#</th>
            <th>Claim ID</th>
            <th>Patient ID</th>
            <th>Date of Service</th>
            <th>CPT</th>
            <th>Issue Found &amp; Rule Source</th>
            <th>Severity</th>
            <th>Suggested Fix</th>
          </tr></thead>
          <tbody id="resultsBody"></tbody>
        </table>
      </div>
    </div>
    <div class="clean-panel" id="cleanPanel" onclick="toggleClean()">
      <div class="clean-panel-info">
        <div class="clean-icon">&#x2705;</div>
        <div><div class="clean-title" id="cleanTitle">0 Clean Claims</div><div class="clean-sub">No issues found</div></div>
      </div>
      <div class="clean-toggle" id="cleanToggle">Show &#x25BC;</div>
    </div>
    <div class="clean-list-wrap" id="cleanList">
      <table class="clean-tbl"><thead><tr><th>#</th><th>Claim ID</th><th>Patient ID</th><th>Date of Service</th><th>CPT</th></tr></thead><tbody id="cleanBody"></tbody></table>
    </div>
    <button class="btn-new" onclick="resetScrubber()">&#x21A9; Analyze Another File</button>
    <div id="anonGate" style="display:none;margin-top:1.25rem;border-radius:14px;overflow:hidden;box-shadow:0 4px 24px rgba(15,23,42,.15)">
      <div style="background:linear-gradient(135deg,#0f172a,#0d2144);padding:2rem;text-align:center">
        <div style="font-size:2rem;margin-bottom:.5rem">&#x1F512;</div>
        <h3 style="color:#fff;font-size:1.2rem;font-weight:800;margin-bottom:.5rem" id="anonGateTitle">Sign up to see all flagged claims</h3>
        <p style="color:rgba(255,255,255,.75);font-size:.92rem;max-width:440px;margin:0 auto 1.25rem" id="anonGateMsg">You're seeing the first 3 flagged claims. Start your free 14-day trial to see the full report and all issues found.</p>
        <div style="display:flex;gap:.75rem;justify-content:center;flex-wrap:wrap">
          <a href="/signup" style="display:inline-block;padding:.75rem 1.6rem;background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));color:#fff;border-radius:8px;font-weight:700;font-size:.95rem;text-decoration:none">Start Free 14-Day Trial &#x2192;</a>
          <a href="/login" style="display:inline-block;padding:.75rem 1.4rem;background:rgba(255,255,255,.1);color:#fff;border:1.5px solid rgba(255,255,255,.3);border-radius:8px;font-weight:600;font-size:.9rem;text-decoration:none">Sign In</a>
        </div>
      </div>
    </div>
  </div>

  <!-- Batch results section -->
  <div id="batchResultsSection" style="display:none">
    <div class="summary-bar" id="batchSummaryBar">
      <div class="summary-stats">
        <div class="summary-stat"><div class="num num-blue" id="bStatTotal">0</div><div class="lbl">Total Claims</div></div>
        <div class="summary-stat"><div class="num num-amber" id="bStatFlagged">0</div><div class="lbl">Total Flagged</div></div>
        <div class="sep"></div>
        <div class="summary-stat"><div class="num num-red" id="bStatHigh">0</div><div class="lbl">High</div></div>
        <div class="summary-stat"><div class="num num-amber" id="bStatMed">0</div><div class="lbl">Medium</div></div>
        <div class="summary-stat"><div class="num num-blue" id="bStatLow">0</div><div class="lbl">Low</div></div>
      </div>
      <button class="btn-download" onclick="downloadBatchReport()">&#x2B07; Download Batch Report</button>
    </div>
    <div class="card" style="padding:0;overflow:hidden">
      <div class="table-wrap">
        <table id="batchResultsTable">
          <thead><tr>
            <th>Source File</th>
            <th style="width:48px">#</th>
            <th>Claim ID</th>
            <th>Patient ID</th>
            <th>Date of Service</th>
            <th>CPT</th>
            <th>Issue Found</th>
            <th>Severity</th>
            <th>Suggested Fix</th>
          </tr></thead>
          <tbody id="batchResultsBody"></tbody>
        </table>
      </div>
    </div>
    <button class="btn-new" onclick="resetBatch()">&#x21A9; New Batch</button>
  </div>
</div>
${FOOTER}
<script>
let selFile=null,lastResults=null,lastTotal=0,lastClean=[],lastPayer='general',lastPayerLabel='General',lastAppliedPayer='general';
const PAYER_LABELS={general:'General',medicare:'Medicare',medicaid:'Medicaid',bcbs:'Blue Cross Blue Shield',uhc:'United Healthcare',aetna:'Aetna',cigna:'Cigna',humana:'Humana'};
const isPro=${JSON.stringify(isPro)};
// Single-file drag/drop
const dropZone=document.getElementById('dropZone');
const fileInput=document.getElementById('fileInput');
if(dropZone){
dropZone.addEventListener('dragover',e=>{e.preventDefault();dropZone.classList.add('dragover')});
dropZone.addEventListener('dragleave',()=>dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop',e=>{e.preventDefault();dropZone.classList.remove('dragover');if(e.dataTransfer.files.length)handleFile(e.dataTransfer.files[0])});
}
if(fileInput)fileInput.addEventListener('change',e=>{if(e.target.files.length)handleFile(e.target.files[0])});
// Batch drag/drop
const batchDropZone=document.getElementById('batchDropZone');
const batchFileInput=document.getElementById('batchFileInput');
if(batchDropZone){
  batchDropZone.addEventListener('dragover',e=>{e.preventDefault();batchDropZone.classList.add('dragover')});
  batchDropZone.addEventListener('dragleave',()=>batchDropZone.classList.remove('dragover'));
  batchDropZone.addEventListener('drop',e=>{e.preventDefault();batchDropZone.classList.remove('dragover');if(e.dataTransfer.files.length)addBatchFiles(Array.from(e.dataTransfer.files))});
}
if(batchFileInput)batchFileInput.addEventListener('change',e=>{if(e.target.files.length){addBatchFiles(Array.from(e.target.files));e.target.value='';}});
// Batch mode state
let batchFiles=[];
let batchAllResults=[];
// Restore session state
(function(){
  const saved=sessionStorage.getItem('clinicos_batch_mode');
  if(saved==='true'&&isPro){
    const toggle=document.getElementById('batchToggleInput');
    if(toggle){toggle.checked=true;setBatchMode(true);}
  }
})();
function onPayerChange(){
  const v=document.getElementById('payerSelect').value;
  lastPayer=v;lastPayerLabel=PAYER_LABELS[v]||v;
  const banner=document.getElementById('payerProBanner');
  if(banner)banner.style.display=(v!=='general')?'block':'none';
}
// ─── Batch Mode ──────────────────────────────────────────────────────────────
function showBatchUpgradeTip(){
  const tip=document.getElementById('batchUpgradeTip');
  if(tip){tip.style.display='block';setTimeout(()=>{tip.style.display='none';},5000);}
}
function onBatchToggleChange(checked){
  if(!isPro){document.getElementById('batchToggleInput').checked=false;showBatchUpgradeTip();return;}
  sessionStorage.setItem('clinicos_batch_mode',checked?'true':'false');
  setBatchMode(checked);
}
function setBatchMode(on){
  const single=document.getElementById('singleUploadSection');
  const batch=document.getElementById('batchUploadSection');
  const batchRes=document.getElementById('batchResultsSection');
  const singleRes=document.getElementById('resultsSection');
  if(on){
    if(single)single.style.display='none';
    if(batch)batch.style.display='block';
    // Hide single-file analyze button when in batch mode
    const ab=document.getElementById('analyzeBtn');if(ab)ab.style.display='none';
    const fs=document.getElementById('fileSelected');if(fs)fs.classList.remove('visible');
    if(singleRes)singleRes.classList.remove('visible');
  }else{
    if(single)single.style.display='block';
    if(batch)batch.style.display='none';
    const ab=document.getElementById('analyzeBtn');if(ab)ab.style.display='';
    if(batchRes)batchRes.style.display='none';
  }
}
function addBatchFiles(files){
  for(const f of files){
    if(batchFiles.length>=10)break;
    if(!f.name.toLowerCase().endsWith('.csv'))continue;
    if(batchFiles.find(b=>b.name===f.name))continue;
    batchFiles.push({file:f,name:f.name,size:f.size,status:'queued',result:null,errorMsg:''});
  }
  renderBatchQueue();
  const btn=document.getElementById('startBatchBtn');
  if(btn)btn.disabled=batchFiles.length===0;
  const wrap=document.getElementById('batchQueueWrap');
  if(wrap)wrap.style.display=batchFiles.length>0?'block':'none';
}
function removeBatchFile(idx){
  batchFiles.splice(idx,1);
  renderBatchQueue();
  const btn=document.getElementById('startBatchBtn');
  if(btn)btn.disabled=batchFiles.length===0;
  const wrap=document.getElementById('batchQueueWrap');
  if(wrap)wrap.style.display=batchFiles.length>0?'block':'none';
}
function renderBatchQueue(){
  const q=document.getElementById('batchQueue');if(!q)return;
  if(batchFiles.length===0){q.innerHTML='';return;}
  q.innerHTML=batchFiles.map((bf,i)=>{
    const statusHtml={
      'queued':'<span class="batch-status bs-queued">Queued</span>',
      'processing':'<span class="batch-status bs-processing"><span class="batch-spinner"></span> Processing...</span>',
      'done':'<span class="batch-status bs-done">&#x2713; Done</span>',
      'error':'<span class="batch-status bs-error" title="'+esc(bf.errorMsg)+'">&#x26A0; Error</span>'
    }[bf.status]||'';
    const canRemove=bf.status==='queued';
    return '<div class="batch-file-row">'+
      '<span style="font-size:1rem;flex-shrink:0">&#x1F4C4;</span>'+
      '<span class="bfr-name">'+esc(bf.name)+'</span>'+
      '<span class="bfr-size">'+fmtBytes(bf.size)+'</span>'+
      statusHtml+
      (canRemove?'<button class="btn-remove-file" onclick="removeBatchFile('+i+')" title="Remove">&#x2715;</button>':'<span style="width:28px"></span>')+
      '</div>';
  }).join('');
}
async function startBatch(){
  if(batchFiles.length===0)return;
  const payer=document.getElementById('payerSelect')?.value||'general';
  const btn=document.getElementById('startBatchBtn');
  if(btn)btn.disabled=true;
  const progressWrap=document.getElementById('batchProgressWrap');
  if(progressWrap)progressWrap.style.display='block';
  batchAllResults=[];
  const total=batchFiles.length;
  for(let i=0;i<total;i++){
    const bf=batchFiles[i];
    bf.status='processing';
    renderBatchQueue();
    const label=document.getElementById('batchProgressLabel');
    const pct=document.getElementById('batchProgressPct');
    const fill=document.getElementById('batchProgressFill');
    if(label)label.textContent='Processing file '+(i+1)+' of '+total+'...';
    const pctVal=Math.round(i/total*100);
    if(pct)pct.textContent=pctVal+'%';
    if(fill)fill.style.width=pctVal+'%';
    try{
      const fd=new FormData();fd.append('file',bf.file);fd.append('payer',payer);
      const r=await fetch('/api/scrub',{method:'POST',body:fd});
      const d=await r.json();
      if(!r.ok)throw new Error(d.error||'Analysis failed');
      bf.status='done';bf.result=d;
      batchAllResults.push({fileName:bf.name,data:d});
    }catch(err){
      bf.status='error';bf.errorMsg=err.message||'Analysis failed';
    }
    renderBatchQueue();
  }
  // Final progress
  const fill=document.getElementById('batchProgressFill');if(fill)fill.style.width='100%';
  const pct=document.getElementById('batchProgressPct');if(pct)pct.textContent='100%';
  const label=document.getElementById('batchProgressLabel');if(label)label.textContent='Batch complete!';
  // Render consolidated results
  renderBatchResults();
  // Save batch report
  const successFiles=batchAllResults.filter(r=>r.data);
  if(successFiles.length>0)saveBatchReport(successFiles,payer);
}
function renderBatchResults(){
  const successFiles=batchAllResults.filter(r=>r.data);
  if(successFiles.length===0)return;
  let totalClaims=0,allFlagged=[];
  for(const f of successFiles){
    totalClaims+=f.data.total_rows||0;
    for(const row of(f.data.flagged||[])){
      allFlagged.push({...row,source_file:f.fileName});
    }
  }
  const hi=allFlagged.filter(r=>r.severity==='High').length;
  const md=allFlagged.filter(r=>r.severity==='Medium').length;
  const lo=allFlagged.filter(r=>r.severity==='Low').length;
  document.getElementById('bStatTotal').textContent=String(totalClaims);
  document.getElementById('bStatFlagged').textContent=String(allFlagged.length);
  document.getElementById('bStatHigh').textContent=String(hi);
  document.getElementById('bStatMed').textContent=String(md);
  document.getElementById('bStatLow').textContent=String(lo);
  const tb=document.getElementById('batchResultsBody');tb.innerHTML='';
  if(allFlagged.length===0){
    tb.innerHTML='<tr><td colspan="9"><div class="no-issues"><span class="big-check">&#x1F389;</span>No issues found across all files!</div></td></tr>';
  }else{
    for(const row of allFlagged){
      const tr=document.createElement('tr');
      tr.innerHTML=
        '<td style="font-size:.8rem;color:#475569;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(row.source_file)+'">'+esc(row.source_file)+'</td>'+
        '<td style="font-weight:600;color:#94a3b8;font-size:.8rem">'+esc(String(row.row_number||''))+'</td>'+
        '<td style="font-weight:600;color:var(--navy);font-size:.85rem">'+esc(String(row.claim_id||'\u2014'))+'</td>'+
        '<td>'+esc(String(row.patient_id||'\u2014'))+'</td>'+
        '<td style="white-space:nowrap">'+esc(String(row.date_of_service||'\u2014'))+'</td>'+
        '<td><code style="background:#f1f5f9;padding:.15rem .5rem;border-radius:5px;font-size:.85rem;font-weight:600">'+esc(String(row.cpt_code||'\u2014'))+'</code></td>'+
        '<td><div class="issue-type-tag">'+esc(String(row.issue_type||''))+'</div><div class="issue-desc">'+esc(String(row.description||''))+'</div>'+(row.is_custom_rule||row.rule_source==='Custom Rule'?'<span class="custom-rule-badge">&#x1F6E1; Custom Rule: '+esc(String(row.custom_rule_name||row.issue_type||''))+'</span>':'')+' </td>'+
        '<td><span class="sev-badge sev-'+esc(String(row.severity))+'"><span class="sev-dot"></span>'+esc(String(row.severity))+'</span></td>'+
        '<td><div class="fix-text">'+esc(String(row.suggested_fix||'\u2014'))+'</div></td>';
      tb.appendChild(tr);
    }
  }
  document.getElementById('batchResultsSection').style.display='block';
  document.getElementById('batchResultsSection').scrollIntoView({behavior:'smooth',block:'start'});
}
function downloadBatchReport(){
  const successFiles=batchAllResults.filter(r=>r.data);
  if(!successFiles.length)return;
  const payer=PAYER_LABELS[document.getElementById('payerSelect')?.value||'general']||'General';
  const hdrs=['source_file','row_number','claim_id','patient_id','date_of_service','cpt_code','issue_type','severity','rule_source','description','suggested_fix'];
  const allFlagged=[];
  for(const f of successFiles){
    for(const row of(f.data.flagged||[])){
      allFlagged.push({...row,source_file:f.fileName});
    }
  }
  const rows=allFlagged.map(r=>hdrs.map(h=>'"'+String(r[h]||'').replace(/"/g,'""')+'"').join(','));
  const meta=['"ClinicOS AI Batch Scrub Report"','""','"Payer: '+payer+'"','"Files: '+successFiles.length+'"'];
  const csv=[meta.join(','),'',hdrs.join(','),...rows].join('\\n');
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download='clinicos_batch_report_'+new Date().toISOString().slice(0,10)+'.csv';a.click();
}
async function saveBatchReport(files,payer){
  try{
    const allFlagged=[];
    let totalClaims=0;
    for(const f of files){totalClaims+=f.data.total_rows||0;for(const row of(f.data.flagged||[])){allFlagged.push({...row,source_file:f.fileName});}}
    await fetch('/api/save-batch-report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      files:files.map(f=>({name:f.fileName,total_rows:f.data.total_rows||0,flagged_count:(f.data.flagged||[]).length})),
      all_flagged:allFlagged,
      total_claims:totalClaims,
      payer:payer
    })});
  }catch(e){/* non-critical */}
}
function resetBatch(){
  batchFiles=[];batchAllResults=[];
  renderBatchQueue();
  document.getElementById('batchResultsSection').style.display='none';
  const wrap=document.getElementById('batchQueueWrap');if(wrap)wrap.style.display='none';
  const progressWrap=document.getElementById('batchProgressWrap');if(progressWrap)progressWrap.style.display='none';
  const btn=document.getElementById('startBatchBtn');if(btn)btn.disabled=true;
}
function handleFile(f){
  hideErr();
  if(!f.name.toLowerCase().endsWith('.csv')){showErr('Please upload a .csv file only.');return}
  if(f.size>5*1024*1024){showErr('File is too large. Please upload a CSV under 5MB.');return}
  selFile=f;
  document.getElementById('fileName').textContent=f.name;
  document.getElementById('fileSize').textContent=fmtBytes(f.size);
  document.getElementById('fileSelected').classList.add('visible');
  document.getElementById('analyzeBtn').disabled=false;
}
function fmtBytes(b){if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(1)+' MB'}
function showErr(m){document.getElementById('errorMsg').textContent=m;document.getElementById('errorBanner').classList.add('visible')}
function hideErr(){document.getElementById('errorBanner').classList.remove('visible')}
async function analyzeClaims(){
  if(!selFile)return;
  hideErr();
  lastAppliedPayer=lastPayer;
  document.getElementById('uploadCard').style.display='none';
  document.getElementById('loadingState').classList.add('visible');
  document.getElementById('resultsSection').classList.remove('visible');
  try{
    const fd=new FormData();fd.append('file',selFile);fd.append('payer',lastPayer);
    const r=await fetch('/api/scrub',{method:'POST',body:fd});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Analysis failed');
    renderResults(d);
  }catch(err){
    document.getElementById('loadingState').classList.remove('visible');
    document.getElementById('uploadCard').style.display='block';
    const m=err.message||'';
    if(m.includes('format'))showErr("We couldn't recognize this file's format. Please download the sample CSV to see the expected column headers.");
    else showErr('Analysis temporarily unavailable. Please try again in a moment.');
  }
}
function renderResults(d){
  document.getElementById('loadingState').classList.remove('visible');
  lastResults=d.flagged||[];lastTotal=d.total_rows||0;lastClean=d.clean_rows||[];
  const fl=lastResults,total=lastTotal,clean=lastClean.length;
  const totalFlagged=d.total_flagged||fl.length;
  const hiddenCount=d.hidden_count||0;
  const accessLevel=d.access_level||'anonymous';
  const appliedPayer=d.applied_payer||'general';
  const payerLabel=PAYER_LABELS[appliedPayer]||appliedPayer;
  const hi=fl.filter(r=>r.severity==='High').length;
  const md=fl.filter(r=>r.severity==='Medium').length;
  const lo=fl.filter(r=>r.severity==='Low').length;
  document.getElementById('statFlagged').textContent=totalFlagged;
  document.getElementById('statTotal').textContent=total;
  document.getElementById('statHigh').textContent=hi+(hiddenCount>0?'+':'');
  document.getElementById('statMed').textContent=md+(hiddenCount>0?'+':'');
  document.getElementById('statLow').textContent=lo+(hiddenCount>0?'+':'');
  document.getElementById('statClean').textContent=clean;
  document.getElementById('statPayer').textContent=payerLabel;
  // Show upgrade banner if payer-specific was requested but not applied
  const upgBanner=document.getElementById('payerUpgradeBanner');
  if(upgBanner)upgBanner.style.display=(d.payer_upgrade_prompt&&lastAppliedPayer!=='general')?'block':'none';
  const tb=document.getElementById('resultsBody');tb.innerHTML='';
  if(fl.length===0&&hiddenCount===0){
    tb.innerHTML='<tr><td colspan="8"><div class="no-issues"><span class="big-check">&#x1F389;</span>No issues found in any claims!</div></td></tr>';
  }else{
    for(const row of fl){
      const isCustom=row.is_custom_rule||row.rule_source==='Custom Rule';
      const ruleSource=isCustom
        ?'<span class="custom-rule-badge">&#x1F6E1; Custom Rule: '+esc(row.custom_rule_name||row.issue_type||'')+'</span>'
        :(row.rule_source?'<div style="font-size:.75rem;color:#7c3aed;margin-top:.25rem;font-weight:600">&#x2756; '+esc(row.rule_source)+'</div>':'');
      const tr=document.createElement('tr');
      tr.innerHTML=
        '<td style="font-weight:600;color:#94a3b8;font-size:.8rem">'+esc(row.row_number)+'</td>'+
        '<td style="font-weight:600;color:var(--navy);font-size:.85rem">'+esc(row.claim_id||'&#x2014;')+'</td>'+
        '<td>'+esc(row.patient_id||'&#x2014;')+'</td>'+
        '<td style="white-space:nowrap">'+esc(row.date_of_service||'&#x2014;')+'</td>'+
        '<td><code style="background:#f1f5f9;padding:.15rem .5rem;border-radius:5px;font-size:.85rem;font-weight:600">'+esc(row.cpt_code||'&#x2014;')+'</code></td>'+
        '<td><div class="issue-type-tag">'+esc(row.issue_type||'&#x2014;')+'</div><div class="issue-desc">'+esc(row.description||'')+'</div><div style="margin-top:.3rem">'+ruleSource+'</div></td>'+
        '<td><span class="sev-badge sev-'+esc(row.severity)+'"><span class="sev-dot"></span>'+esc(row.severity)+'</span></td>'+
        '<td><div class="fix-text">'+esc(row.suggested_fix||'&#x2014;')+'</div></td>';
      tb.appendChild(tr);
    }
    if(hiddenCount>0){
      for(let i=0;i<Math.min(hiddenCount,5);i++){
        const tr=document.createElement('tr');
        tr.style.cssText='filter:blur(5px);user-select:none;pointer-events:none;opacity:.7';
        tr.innerHTML='<td style="font-weight:600;color:#94a3b8;font-size:.8rem">'+(fl.length+i+1)+'</td><td style="font-weight:600;color:var(--navy);font-size:.85rem">CLM-XXXXX</td><td>Patient_XXX</td><td style="white-space:nowrap">20XX-XX-XX</td><td><code style="background:#f1f5f9;padding:.15rem .5rem;border-radius:5px;font-size:.85rem;font-weight:600">XXXXX</code></td><td><div class="issue-type-tag">Hidden Issue</div><div class="issue-desc">Sign up to see this issue and suggested fix</div></td><td><span class="sev-badge sev-High"><span class="sev-dot"></span>High</span></td><td><div class="fix-text">Sign up to see the fix</div></td>';
        tb.appendChild(tr);
      }
    }
  }
  if(clean>0){
    document.getElementById('cleanTitle').textContent=clean+' Clean Claim'+(clean!==1?'s':'');
    document.getElementById('cleanPanel').classList.add('visible');
    const cb=document.getElementById('cleanBody');cb.innerHTML='';
    for(const r of lastClean){
      const tr=document.createElement('tr');
      tr.innerHTML='<td>'+esc(String(r.row_number))+'</td><td>'+esc(r.claim_id||'&#x2014;')+'</td><td>'+esc(r.patient_id||'&#x2014;')+'</td><td>'+esc(r.date_of_service||'&#x2014;')+'</td><td>'+esc(r.cpt_code||'&#x2014;')+'</td>';
      cb.appendChild(tr);
    }
  }
  document.getElementById('resultsSection').classList.add('visible');
  const gate=document.getElementById('anonGate');
  if(gate&&hiddenCount>0&&accessLevel==='anonymous'){
    document.getElementById('anonGateTitle').textContent='Sign up to see all '+totalFlagged+' flagged claims';
    document.getElementById('anonGateMsg').textContent='You\'re seeing '+fl.length+' of '+totalFlagged+' flagged claims. Start your free 14-day trial to unlock the full report.';
    gate.style.display='block';
  }
}
function toggleClean(){
  const l=document.getElementById('cleanList');
  l.classList.toggle('open');
  document.getElementById('cleanToggle').textContent=l.classList.contains('open')?'Hide \u25B2':'Show \u25BC';
}
function downloadReport(){
  if(!lastResults)return;
  const payer=PAYER_LABELS[lastAppliedPayer]||lastAppliedPayer;
  const hdrs=['row_number','claim_id','patient_id','date_of_service','cpt_code','issue_type','severity','rule_source','description','suggested_fix'];
  const rows=lastResults.map(r=>hdrs.map(h=>'"'+String(r[h]||'').replace(/"/g,'""')+'"').join(','));
  const meta=['"ClinicOS AI Claim Scrub Report"','""','"Payer: '+payer+'"'];
  const csv=[meta.join(','),'',hdrs.join(','),...rows].join('\\n');
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download='clinicos_scrub_report_'+payer.replace(/\\s+/g,'_').toLowerCase()+'.csv';a.click();
}
function resetScrubber(){
  selFile=null;fileInput.value='';
  document.getElementById('fileSelected').classList.remove('visible');
  document.getElementById('analyzeBtn').disabled=true;
  hideErr();
  document.getElementById('resultsSection').classList.remove('visible');
  document.getElementById('cleanList').classList.remove('open');
  document.getElementById('cleanPanel').classList.remove('visible');
  document.getElementById('uploadCard').style.display='block';
  const upgBanner=document.getElementById('payerUpgradeBanner');if(upgBanner)upgBanner.style.display='none';
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
// ─── PM Connect JS ─────────────────────────────────────────────────────────
function showPmModal(system){
  const id=system==='kareo'?'kareoModal':'advancedmdModal';
  const el=document.getElementById(id);
  if(el){el.style.display='flex';}
}
function closeModal(id){
  const el=document.getElementById(id);
  if(el){el.style.display='none';}
}
async function saveKareo(){
  const ck=document.getElementById('kareoCustomerKey').value.trim();
  const ak=document.getElementById('kareoApiKey').value.trim();
  const errEl=document.getElementById('kareoModalError');
  const btn=document.getElementById('kareoSaveBtn');
  if(!ck||!ak){errEl.style.display='block';errEl.textContent='Both fields are required.';return;}
  btn.disabled=true;btn.textContent='Saving...';
  try{
    const r=await fetch('/api/pm/kareo/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({customer_key:ck,api_key:ak})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Failed to connect');
    location.reload();
  }catch(e){errEl.style.display='block';errEl.textContent=e.message||'Connection failed. Please check your credentials.';btn.disabled=false;btn.textContent='Save & Connect';}
}
async function saveAdvancedMD(){
  const oc=document.getElementById('amdOfficeCode').value.trim();
  const un=document.getElementById('amdUsername').value.trim();
  const pw=document.getElementById('amdPassword').value.trim();
  const an=document.getElementById('amdAppName').value.trim();
  const errEl=document.getElementById('amdModalError');
  const btn=document.getElementById('amdSaveBtn');
  if(!oc||!un||!pw||!an){errEl.style.display='block';errEl.textContent='All fields are required.';return;}
  btn.disabled=true;btn.textContent='Saving...';
  try{
    const r=await fetch('/api/pm/advancedmd/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({office_code:oc,username:un,password:pw,app_name:an})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Failed to connect');
    location.reload();
  }catch(e){errEl.style.display='block';errEl.textContent=e.message||'Connection failed. Please check your credentials.';btn.disabled=false;btn.textContent='Save & Connect';}
}
async function pmFetchClaims(system,daysSelectId){
  const days=parseInt(document.getElementById(daysSelectId)?.value||'7');
  const payer=document.getElementById('payerSelect')?.value||'general';
  const systemLabel={'kareo':'Kareo','advancedmd':'AdvancedMD','drchrono':'DrChrono'}[system]||system;
  const loadEl=document.getElementById('pmLoadingState');
  const errEl=document.getElementById('pmErrorBanner');
  const errMsg=document.getElementById('pmErrorMsg');
  if(loadEl){loadEl.style.display='block';}
  if(errEl){errEl.style.display='none';}
  document.getElementById('pmLoadingMsg').textContent='Fetching claims from '+systemLabel+'...';
  document.getElementById('uploadCard').style.display='none';
  document.getElementById('resultsSection').classList.remove('visible');
  try{
    const r=await fetch('/api/pm/fetch-claims',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({system,days,payer})});
    const d=await r.json();
    if(!r.ok){
      if(loadEl)loadEl.style.display='none';
      if(errEl){errEl.style.display='flex';}
      if(errMsg)errMsg.textContent=d.error||('Failed to fetch claims from '+systemLabel);
      document.getElementById('uploadCard').style.display='block';
      return;
    }
    if(loadEl)loadEl.style.display='none';
    renderResults(d);
  }catch(e){
    if(loadEl)loadEl.style.display='none';
    if(errEl){errEl.style.display='flex';}
    if(errMsg)errMsg.textContent='Failed to fetch claims: '+(e.message||'Unknown error');
    document.getElementById('uploadCard').style.display='block';
  }
}
</script>
<script>navigator.sendBeacon("/api/_ping");</script>
</body></html>`);
});

// ─── /api/scrub ───────────────────────────────────────────────────────────────
function parseCSV(text: string): { headers: string[]; rows: Record<string, string>[] } {
  const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim().split("\n");
  if (lines.length < 2) return { headers: [], rows: [] };
  const headers = parseLine(lines[0]);
  if (headers.length === 0) return { headers: [], rows: [] };
  const rows: Record<string, string>[] = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const values = parseLine(line);
    const row: Record<string, string> = {};
    for (let j = 0; j < headers.length; j++) row[headers[j]] = values[j] ?? "";
    rows.push(row);
  }
  return { headers, rows };
}

function parseLine(line: string): string[] {
  const result: string[] = [];
  let cur = "", inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQ && line[i + 1] === '"') { cur += '"'; i++; } else inQ = !inQ;
    } else if (ch === "," && !inQ) { result.push(cur.trim()); cur = ""; }
    else cur += ch;
  }
  result.push(cur.trim());
  return result;
}

// ─── Payer-specific prompt rules ──────────────────────────────────────────────
function getPayerRules(payer: string): string {
  switch (payer) {
    case "medicare":
      return `
MEDICARE-SPECIFIC RULES (apply in addition to general rules, label each finding with rule_source starting with "Medicare"):
- MUE (Medically Unlikely Edits): flag claims where units exceed typical MUE per claim. Common violations: CPT 99213 > 1 unit, CPT 93000 > 1 unit, CPT 85025 > 1 unit. Label: "Medicare MUE"
- ABN Modifiers: CPT codes that commonly require Advance Beneficiary Notice must have modifier -GA, -GZ, or -GY. Flag high-risk CPTs (20610, 93000, 99213) missing these modifiers. Label: "Medicare Modifier"
- Balance billing: flag claims where billed amount appears to significantly exceed Medicare fee schedule norms (advisory warning, not hard denial). Label: "Medicare Balance Billing"
- LCD/NCD coverage: flag CPT 93306 (echocardiography) without a matching heart disease ICD-10 code. Label: "Medicare LCD/NCD"`;
    case "medicaid":
      return `
MEDICAID-SPECIFIC RULES (apply in addition to general rules, label each finding with rule_source starting with "Medicaid"):
- Prior authorization: flag CPT codes in imaging range 70000-79999, surgical procedure codes, and DME codes as likely requiring Medicaid prior authorization. Label: "Medicaid Prior Auth"
- Timely filing advisory: if date_of_service is present and over 60 days ago, flag as advisory warning approaching Medicaid timely filing limits (typically 90 days, varies by state). Label: "Medicaid Timely Filing"
- Referral requirements: flag specialist visit CPT codes 99241-99245 without a referral indicator in the data. Label: "Medicaid Referral"`;
    case "bcbs":
      return `
BLUE CROSS BLUE SHIELD RULES (apply in addition to general rules, label each finding with rule_source starting with "BCBS"):
- Bundling: BCBS frequently bundles codes Medicare pays separately. Flag common pairs: 99213 + 36415 on same DOS (blood draw often bundled), 93000 + 99213 on same DOS (subject to bundling review). Label: "BCBS Bundling"
- Prior auth: flag high-cost imaging CPTs (MRI 70553, CT 74178), surgical procedures, and sleep studies (95810) as likely requiring BCBS prior authorization. Label: "BCBS Prior Auth"
- Referral: flag specialist CPT codes (99241-99245) without referral indicator. Label: "BCBS Referral"`;
    case "uhc":
      return `
UNITED HEALTHCARE RULES (apply in addition to general rules, label each finding with rule_source starting with "UHC"):
- Modifier specificity: UHC requires X-modifiers instead of -59. Flag any claim using modifier -59 — suggest XE (separate encounter), XS (separate structure), XP (separate practitioner), or XU (unusual non-overlapping service) as appropriate. Label: "UHC Modifier"
- Prior auth: flag outpatient surgery codes, advanced imaging CPTs, and behavioral health codes as likely requiring UHC prior authorization. Label: "UHC Prior Auth"
- NCCI-like edits: flag common code pairs that UHC denies similarly to NCCI edits (e.g. comprehensive + component codes same DOS same provider). Label: "UHC NCCI Edit"`;
    case "aetna":
      return `
AETNA-SPECIFIC RULES (apply in addition to general rules, label each finding with rule_source starting with "Aetna"):
- Advanced imaging: flag imaging CPTs (MRI, CT, PET) without a prior auth indicator. Label: "Aetna Prior Auth"
- High-cost surgical codes: flag surgical procedure codes as likely requiring Aetna authorization. Label: "Aetna Auth Required"
- Modifier -25 scrutiny: flag E&M code + surgical/procedure code on the same DOS where modifier -25 is used on the E&M — Aetna heavily scrutinizes these combinations. Label: "Aetna Modifier -25"`;
    case "cigna":
      return `
CIGNA-SPECIFIC RULES (apply in addition to general rules, label each finding with rule_source starting with "Cigna"):
- Bundled service pairs: flag CPT code combinations Cigna commonly denies as bundled (comprehensive + component codes same DOS). Label: "Cigna Bundling"
- Behavioral health: flag behavioral health CPT codes (90832-90853, 90791-90792) without proper authorization indicators. Label: "Cigna Behavioral Health Auth"
- Modifier -59 specificity: Cigna, like UHC, prefers specificity. Flag modifier -59 usage and suggest more specific X-modifiers (XE, XS, XP, XU). Label: "Cigna Modifier"`;
    case "humana":
      return `
HUMANA-SPECIFIC RULES (apply in addition to general rules, label each finding with rule_source starting with "Humana"):
- Medicare Advantage overlap: Humana MA plans follow Medicare rules plus Humana additions. Apply Medicare MUE rules (CPT 99213 > 1 unit, 93000 > 1 unit), ABN modifier requirements, and LCD/NCD coverage gaps. Label: "Humana MA/Medicare"
- DME and imaging prior auth: flag DME codes (E0100-E9999) and imaging CPTs (70000-79999) as likely requiring Humana prior authorization. Label: "Humana Prior Auth"`;
    default:
      return "";
  }
}

app.post("/api/scrub", async (c) => {
  // Read-only users cannot upload/run the scrubber
  const scrubUserRo = await getCurrentUser(c);
  if (isReadOnly(scrubUserRo)) {
    return c.json({ error: "View only — contact your Admin to request access" }, 403);
  }
  try {
    const formData = await c.req.formData();
    const file = formData.get("file") as File | null;
    if (!file) return c.json({ error: "No file uploaded" }, 400);
    if (file.size > 5 * 1024 * 1024) return c.json({ error: "File too large (5MB max)" }, 400);

    const requestedPayer = ((formData.get("payer") as string) || "general").toLowerCase().trim();
    const validPayers = ["general","medicare","medicaid","bcbs","uhc","aetna","cigna","humana"];
    const payer = validPayers.includes(requestedPayer) ? requestedPayer : "general";

    // Check user plan to determine if payer-specific rules apply
    const scrubUserEarly = await getCurrentUser(c);
    const accessLevelEarly = await getUserAccessLevel(c.env.DB, scrubUserEarly?.user_id ?? null);
    const isProfessional = scrubUserEarly ? await (async () => {
      const row = await c.env.DB.prepare("SELECT plan FROM users WHERE id = ?").bind(scrubUserEarly.user_id).first<{ plan: string }>();
      const p = (row?.plan || "").toLowerCase();
      return p === "professional" || p === "pro";
    })() : false;

    // Apply payer-specific rules only for Professional plan users
    const appliedPayer = (isProfessional && payer !== "general") ? payer : "general";
    const payerUpgradePrompt = !isProfessional && payer !== "general";

    const csvText = await file.text();
    const { headers, rows } = parseCSV(csvText);

    if (headers.length === 0) {
      return c.json({ error: "We couldn't recognize this file's format. Please download the sample CSV to see the expected column headers." }, 422);
    }
    const knownFields = ["claim_id","patient_id","cpt_code","date_of_service","icd10","rendering_npi","payer_id","cpt","dos","patient"];
    const headerLower = headers.map(h => h.toLowerCase().replace(/\s+/g,"_"));
    const hasKnown = knownFields.some(f => headerLower.some(h => h.includes(f)));
    if (!hasKnown) {
      return c.json({ error: "We couldn't recognize this file's format. Please download the sample CSV to see the expected column headers." }, 422);
    }

    const claims = rows.slice(0, 100);
    const totalRows = claims.length;
    const claimsJson = JSON.stringify(claims.map((row, i) => ({ row_number: i + 2, ...row })));

    const payerRules = getPayerRules(appliedPayer);
    const payerContext = appliedPayer !== "general"
      ? `\nSelected payer: ${appliedPayer.toUpperCase()} — apply payer-specific rules below in addition to general rules.`
      : "\nSelected payer: General — apply general rules only.";

    const systemPrompt = `You are a senior medical billing compliance expert and certified professional coder (CPC) with 20+ years of experience. You analyze medical claims for errors that cause denials, audit flags, or payment delays.`;

    const today = new Date().toISOString().split("T")[0];
    const userPrompt = `Analyze these medical claims for billing errors and denial risks.${payerContext}

CSV headers: ${headers.join(", ")}

Claims data:
${claimsJson}

GENERAL RULES — check for:
1. Required field errors: missing patient_id, date_of_service, rendering_npi, payer_id, cpt_code, icd10_code, place_of_service
2. Modifier errors: bilateral procedures missing -50, multiple procedures same DOS missing -51, anesthesia missing AA/QZ/QK, E&M -25 with no separate procedure, missing -59 for distinct services
3. Invalid CPT combos: mutually exclusive pairs same DOS/provider (e.g. 99213+99214), component codes with comprehensive codes
4. ICD-10/CPT mismatches: orthopedic procedure with no musculoskeletal dx, preventive CPT with sick visit dx, mental health CPT with non-behavioral dx
5. Duplicate claims: same patient_id + date_of_service + cpt_code appearing more than once
6. Date logic errors: date_of_service in the future (today is ${today}), DOS before patient DOB
7. Place of service errors: telehealth CPTs (99441-99443, 99421-99423) billed without POS 02 or 10
8. Units issues: units > 1 for E&M codes (99201-99499), zero or negative units
9. Coordination of benefits: secondary_payer present but primary_payer blank
${payerRules}

Return ONLY a JSON object with this structure:
{"flagged":[{"row_number":<int>,"claim_id":"<str|null>","patient_id":"<str|null>","date_of_service":"<str|null>","cpt_code":"<str|null>","issue_type":"<short label>","severity":"High|Medium|Low","rule_source":"<e.g. 'General Rule', 'Medicare MUE', 'UHC Modifier', 'BCBS Bundling', etc.>","description":"<specific explanation>","suggested_fix":"<actionable fix>"}]}

For rule_source: use "General Rule" for issues from the general ruleset, or the payer-specific label (e.g. "Medicare MUE", "UHC Modifier", "BCBS Bundling") for payer-specific findings.
Severity: High=will likely cause denial/audit. Medium=likely reduced payment or delay. Low=best-practice violation.
One entry per issue (a claim with 2 issues = 2 entries).
If no issues found, return {"flagged":[]}.
Return ONLY the JSON object.`;

    const aiResp = await fetch(
      `${c.env.LAUNCHYARD_API_BASE_URL}/v1/ai/openai/v1/chat/completions`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${c.env.LAUNCHYARD_API_KEY}` },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userPrompt }],
          temperature: 0.1,
          response_format: { type: "json_object" },
          max_tokens: 4096,
        }),
      }
    );

    if (aiResp.status === 402) return c.json({ error: "Analysis temporarily unavailable. Please try again in a moment." }, 503);
    if (!aiResp.ok) {
      console.error("AI error:", aiResp.status, await aiResp.text());
      return c.json({ error: "Analysis temporarily unavailable. Please try again in a moment." }, 503);
    }

    const aiData = await aiResp.json() as { choices: Array<{ message: { content: string } }> };
    let flagged: Array<Record<string, unknown>> = [];
    try {
      const content = aiData.choices?.[0]?.message?.content || "{}";
      const cleaned = content.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "").trim();
      const parsed = JSON.parse(cleaned);
      flagged = Array.isArray(parsed.flagged) ? parsed.flagged : [];
    } catch (e) {
      console.error("Parse error:", e);
      return c.json({ error: "Analysis temporarily unavailable. Please try again in a moment." }, 503);
    }

    const flaggedNums = new Set(flagged.map((f) => Number(f.row_number)));
    const cleanRows = claims.map((row, i) => ({
      row_number: i + 2,
      claim_id: row.claim_id || null,
      patient_id: row.patient_id || null,
      date_of_service: row.date_of_service || null,
      cpt_code: row.cpt_code || null,
    })).filter((r) => !flaggedNums.has(r.row_number));

    // Apply custom rules for Professional plan users
    if (scrubUserEarly && isProfessional) {
      try {
        const acctId = scrubUserEarly.account_id || scrubUserEarly.user_id;
        const customRulesResult = await c.env.DB.prepare(
          "SELECT * FROM custom_rules WHERE account_id = ? AND is_active = 1 ORDER BY created_at ASC"
        ).bind(acctId).all<CustomRule>();
        const customRules = customRulesResult.results || [];
        if (customRules.length > 0) {
          const customFlags = applyCustomRules(claims, customRules, appliedPayer);
          // Merge custom flags — deduplicate by row_number+rule_name
          for (const cf of customFlags) {
            flagged.push(cf as Record<string, unknown>);
          }
          // Re-sort by row_number
          flagged.sort((a, b) => Number(a.row_number) - Number(b.row_number));
          // Rebuild cleanRows to exclude newly flagged rows
          const flaggedNumsUpdated = new Set(flagged.map(f => Number(f.row_number)));
          cleanRows.splice(0, cleanRows.length, ...claims.map((row, i) => ({
            row_number: i + 2,
            claim_id: row.claim_id || null,
            patient_id: row.patient_id || null,
            date_of_service: row.date_of_service || null,
            cpt_code: row.cpt_code || null,
          })).filter(r => !flaggedNumsUpdated.has(r.row_number)));
        }
      } catch (ruleErr) {
        console.error("Custom rules error:", ruleErr);
        // Non-fatal — continue without custom rules
      }
    }

    // Save report for logged-in users (reuse scrubUserEarly)
    if (scrubUserEarly) {
      const reportId = generateId();
      try {
        await c.env.DB.prepare(
          "INSERT INTO claim_reports (id, user_id, filename, total_claims, flagged_count, results_json, created_at) VALUES (?, ?, ?, ?, ?, ?, unixepoch())"
        ).bind(reportId, scrubUserEarly.user_id, file.name, totalRows, flagged.length, JSON.stringify({ flagged, clean_rows: cleanRows, payer: appliedPayer })).run();
      } catch (saveErr) {
        console.error("Failed to save report:", saveErr);
      }
    }

    const accessLevel = accessLevelEarly;
    const totalFlagged = flagged.length;
    const ANON_LIMIT = 3;
    let visibleFlagged = flagged;
    let hiddenCount = 0;
    if (accessLevel === 'anonymous' && flagged.length > ANON_LIMIT) {
      visibleFlagged = flagged.slice(0, ANON_LIMIT);
      hiddenCount = flagged.length - ANON_LIMIT;
    }

    return c.json({ total_rows: totalRows, flagged: visibleFlagged, clean_rows: cleanRows, total_flagged: totalFlagged, hidden_count: hiddenCount, access_level: accessLevel, applied_payer: appliedPayer, payer_upgrade_prompt: payerUpgradePrompt });
  } catch (err) {
    console.error("Scrub error:", err);
    return c.json({ error: "Analysis temporarily unavailable. Please try again in a moment." }, 500);
  }
});

// ─── /api/save-batch-report ───────────────────────────────────────────────────
app.post("/api/save-batch-report", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  if (isReadOnly(user)) return c.json({ error: "View only" }, 403);
  // Verify professional plan
  const planRow = await c.env.DB.prepare("SELECT plan FROM users WHERE id = ?").bind(user.user_id).first<{ plan: string }>();
  const p = (planRow?.plan || "").toLowerCase();
  const isBatchPro = p === "professional" || p === "pro";
  if (!isBatchPro) return c.json({ error: "Professional plan required" }, 403);
  try {
    const body = await c.req.json() as {
      files: Array<{ name: string; total_rows: number; flagged_count: number }>;
      all_flagged: Array<Record<string, unknown>>;
      total_claims: number;
      payer: string;
    };
    const { files, all_flagged, total_claims, payer } = body;
    if (!files || !Array.isArray(files) || files.length === 0) return c.json({ error: "No files" }, 400);
    const flaggedCount = all_flagged?.length || 0;
    const dateStr = new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
    const label = `Batch — ${dateStr} — ${files.length} file${files.length !== 1 ? "s" : ""}, ${total_claims} claims, ${flaggedCount} flagged`;
    const reportId = generateId();
    const resultsJson = JSON.stringify({
      flagged: all_flagged || [],
      clean_rows: [],
      payer: payer || "general",
      is_batch: true,
      batch_files: files,
    });
    await c.env.DB.prepare(
      "INSERT INTO claim_reports (id, user_id, filename, total_claims, flagged_count, results_json, created_at) VALUES (?, ?, ?, ?, ?, ?, unixepoch())"
    ).bind(reportId, user.user_id, label, total_claims, flaggedCount, resultsJson).run();
    return c.json({ ok: true, report_id: reportId });
  } catch (err) {
    console.error("Save batch report error:", err);
    return c.json({ error: "Failed to save" }, 500);
  }
});

// ─── Auth styles shared ────────────────────────────────────────────────────────
const AUTH_STYLES = `
body{background:#f1f5f9}
.auth-wrap{min-height:calc(100vh - 80px);display:flex;align-items:center;justify-content:center;padding:2rem}
.auth-card{background:#fff;border-radius:16px;border:1px solid #e2e8f0;padding:2.5rem;width:100%;max-width:440px;box-shadow:0 8px 32px rgba(0,0,0,.07)}
.auth-logo{text-align:center;margin-bottom:2rem}
.auth-logo .logo-icon{width:48px;height:48px;background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));border-radius:12px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:22px;margin:0 auto .75rem}
.auth-logo h2{font-size:1.5rem;font-weight:800;color:var(--navy);margin-bottom:.3rem}
.auth-logo p{color:var(--gray-dark);font-size:.9rem}
.form-group{margin-bottom:1.25rem}
.form-group label{display:block;font-weight:600;color:var(--navy);margin-bottom:.4rem;font-size:.9rem}
.form-group input{width:100%;padding:.85rem 1rem;border:2px solid #e2e8f0;border-radius:8px;font-size:.95rem;font-family:inherit;transition:border-color .2s;outline:none;color:#334155}
.form-group input:focus{border-color:var(--electric-blue)}
.auth-submit{width:100%;padding:1rem;background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:700;cursor:pointer;transition:all .2s ease;margin-top:.5rem}
.auth-submit:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(2,132,199,.3)}
.auth-footer{text-align:center;margin-top:1.5rem;color:var(--gray-dark);font-size:.9rem}
.auth-footer a{color:var(--electric-blue);font-weight:600;text-decoration:none}
.auth-footer a:hover{text-decoration:underline}
.auth-error{background:#fef2f2;border:1.5px solid #fca5a5;border-radius:8px;padding:.85rem 1rem;color:#dc2626;font-size:.88rem;margin-bottom:1.25rem}
.auth-success{background:#f0fdf4;border:1.5px solid #bbf7d0;border-radius:8px;padding:.85rem 1rem;color:#166534;font-size:.88rem;margin-bottom:1.25rem}
`;

// ─── Signup ────────────────────────────────────────────────────────────────────
app.get("/signup", async (c) => {
  const user = await getCurrentUser(c);
  if (user) return c.redirect("/my-claims");
  const error = new URL(c.req.url).searchParams.get("error") || "";
  const errorMsg = error === "exists" ? "An account with that email already exists." : error === "short" ? "Password must be at least 8 characters." : error === "invalid" ? "Please enter a valid email address." : "";
  return c.html(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Sign Up &#x2014; ClinicOS AI</title><style>${SHARED_STYLES}${AUTH_STYLES}</style></head><body>${buildNav(null)}
<div class="auth-wrap"><div class="auth-card">
  <div class="auth-logo"><div class="logo-icon">&#x26A1;</div><h2>Create your account</h2><p>Save reports and track your claim history</p></div>
  ${errorMsg ? `<div class="auth-error">&#x26A0;&#xFE0F; ${escHtml(errorMsg)}</div>` : ""}
  <form method="POST" action="/signup">
    <div class="form-group"><label for="email">Work Email</label><input type="email" id="email" name="email" placeholder="you@clinic.com" required autocomplete="email"></div>
    <div class="form-group"><label for="password">Password</label><input type="password" id="password" name="password" placeholder="At least 8 characters" required autocomplete="new-password" minlength="8"></div>
    <button type="submit" class="auth-submit">Create Account &#x2192;</button>
  </form>
  <div class="auth-footer">Already have an account? <a href="/login">Sign in</a></div>
</div></div>
${FOOTER}<script>navigator.sendBeacon("/api/_ping");</script></body></html>`);
});

app.post("/signup", async (c) => {
  const form = await c.req.formData();
  const email = (form.get("email") as string || "").toLowerCase().trim();
  const password = form.get("password") as string || "";
  if (!email.includes("@") || email.length < 5) return c.redirect("/signup?error=invalid");
  if (password.length < 8) return c.redirect("/signup?error=short");
  const existing = await c.env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
  if (existing) return c.redirect("/signup?error=exists");
  const userId = generateId();
  const salt = generateId();
  const hash = await hashPassword(password, salt);
  await c.env.DB.prepare("INSERT INTO users (id, email, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, unixepoch())").bind(userId, email, hash, salt).run();
  // Create session
  const sessionId = generateId() + generateId();
  const expiresAt = Math.floor(Date.now() / 1000) + 30 * 24 * 3600;
  await c.env.DB.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)").bind(sessionId, userId, expiresAt).run();
  return new Response(null, {
    status: 302,
    headers: {
      Location: "/my-claims",
      "Set-Cookie": `clinicios_session=${sessionId}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${30 * 24 * 3600}; Secure`,
    },
  });
});

// ─── Login ─────────────────────────────────────────────────────────────────────
app.get("/login", async (c) => {
  const user = await getCurrentUser(c);
  if (user) return c.redirect("/my-claims");
  const url = new URL(c.req.url);
  const error = url.searchParams.get("error") || "";
  const next = url.searchParams.get("next") || "/my-claims";
  const resetSuccess = url.searchParams.get("reset") === "1";
  const errorMsg = error === "invalid" ? "Invalid email or password." : "";
  return c.html(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Sign In &#x2014; ClinicOS AI</title><style>${SHARED_STYLES}${AUTH_STYLES}</style></head><body>${buildNav(null)}
<div class="auth-wrap"><div class="auth-card">
  <div class="auth-logo"><div class="logo-icon">&#x26A1;</div><h2>Welcome back</h2><p>Sign in to view your claim history</p></div>
  ${resetSuccess ? `<div class="auth-success">&#x2705; Your password has been reset. Please sign in with your new password.</div>` : ""}
  ${errorMsg ? `<div class="auth-error">&#x26A0;&#xFE0F; ${escHtml(errorMsg)}</div>` : ""}
  <form method="POST" action="/login">
    <input type="hidden" name="next" value="${escHtml(next)}">
    <div class="form-group"><label for="email">Email</label><input type="email" id="email" name="email" placeholder="you@clinic.com" required autocomplete="email"></div>
    <div class="form-group" style="position:relative">
      <label for="password" style="display:flex;justify-content:space-between;align-items:center">Password <a href="/forgot-password" style="font-size:.82rem;font-weight:500;color:var(--electric-blue);text-decoration:none">Forgot your password?</a></label>
      <input type="password" id="password" name="password" placeholder="Your password" required autocomplete="current-password">
    </div>
    <button type="submit" class="auth-submit">Sign In &#x2192;</button>
  </form>
  <div class="auth-footer">Don't have an account? <a href="/signup">Create one free</a></div>
</div></div>
${FOOTER}<script>navigator.sendBeacon("/api/_ping");</script></body></html>`);
});

app.post("/login", async (c) => {
  const form = await c.req.formData();
  const email = (form.get("email") as string || "").toLowerCase().trim();
  const password = form.get("password") as string || "";
  const next = (form.get("next") as string || "/my-claims").replace(/[^a-zA-Z0-9\-_\/]/g, "");
  const row = await c.env.DB.prepare("SELECT id, password_hash, password_salt FROM users WHERE email = ?").bind(email).first<{ id: string; password_hash: string; password_salt: string }>();
  if (!row) return c.redirect("/login?error=invalid");
  const ok = await verifyPassword(password, row.password_salt, row.password_hash);
  if (!ok) return c.redirect("/login?error=invalid");
  const sessionId = generateId() + generateId();
  const expiresAt = Math.floor(Date.now() / 1000) + 30 * 24 * 3600;
  await c.env.DB.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)").bind(sessionId, row.id, expiresAt).run();
  return new Response(null, {
    status: 302,
    headers: {
      Location: next || "/my-claims",
      "Set-Cookie": `clinicios_session=${sessionId}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${30 * 24 * 3600}; Secure`,
    },
  });
});

// ─── Logout ────────────────────────────────────────────────────────────────────
app.post("/logout", async (c) => {
  const cookieHeader = c.req.header("cookie") || "";
  const cookies = parseCookies(cookieHeader);
  const sessionId = cookies["clinicios_session"];
  if (sessionId) {
    await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sessionId).run().catch(() => {});
  }
  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": "clinicios_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure",
    },
  });
});

// ─── Forgot Password ──────────────────────────────────────────────────────────
app.get("/forgot-password", async (c) => {
  const url = new URL(c.req.url);
  const sent = url.searchParams.get("sent") === "1";
  return c.html(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Forgot Password &#x2014; ClinicOS AI</title><style>${SHARED_STYLES}${AUTH_STYLES}</style></head><body>${buildNav(null)}
<div class="auth-wrap"><div class="auth-card">
  <div class="auth-logo"><div class="logo-icon">&#x1F511;</div><h2>Reset your password</h2><p>Enter your email and we'll send a reset link</p></div>
  ${sent ? `<div class="auth-success">&#x2705; If that email is registered, you'll receive a reset link shortly. Check your inbox (and spam folder).</div>
  <div class="auth-footer"><a href="/login">&#x2190; Back to Sign In</a></div>` :
  `<form method="POST" action="/forgot-password">
    <div class="form-group"><label for="email">Email Address</label><input type="email" id="email" name="email" placeholder="you@clinic.com" required autocomplete="email"></div>
    <button type="submit" class="auth-submit">Send Reset Link &#x2192;</button>
  </form>
  <div class="auth-footer"><a href="/login">&#x2190; Back to Sign In</a></div>`}
</div></div>
${FOOTER}<script>navigator.sendBeacon("/api/_ping");</script></body></html>`);
});

app.post("/forgot-password", async (c) => {
  const form = await c.req.formData();
  const email = (form.get("email") as string || "").toLowerCase().trim();
  // Always redirect with sent=1 to avoid revealing whether email exists
  if (!email.includes("@")) return c.redirect("/forgot-password?sent=1");
  const user = await c.env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first<{ id: string }>();
  if (user) {
    // Generate a secure random token
    const rawBytes = new Uint8Array(32);
    crypto.getRandomValues(rawBytes);
    const token = Array.from(rawBytes).map(b => b.toString(16).padStart(2, "0")).join("");
    const tokenHash = await hashToken(token);
    const tokenId = generateId();
    const expiresAt = Math.floor(Date.now() / 1000) + 3600; // 1 hour
    // Invalidate any existing unused tokens for this user
    await c.env.DB.prepare("DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL").bind(user.id).run().catch(() => {});
    await c.env.DB.prepare("INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)").bind(tokenId, user.id, tokenHash, expiresAt).run();
    const resetUrl = `${c.env.APP_BASE_URL}/reset-password?token=${token}`;
    const emailBody = `Hi,\n\nWe received a request to reset your ClinicOS AI password.\n\nClick the link below to set a new password. This link expires in 1 hour.\n\n${resetUrl}\n\nIf you did not request a password reset, you can safely ignore this email. Your password will not change.\n\n— The ClinicOS AI Team`;
    await fetch(`${c.env.LAUNCHYARD_API_BASE_URL}/v1/public/companies/${c.env.COMPANY_ID}/emails`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${c.env.LAUNCHYARD_API_KEY}` },
      body: JSON.stringify({ to: email, subject: "Reset your ClinicOS AI password", body: emailBody, message_scope: "transactional" }),
    }).catch(err => console.error("Failed to send reset email:", err));
  }
  return c.redirect("/forgot-password?sent=1");
});

// ─── Reset Password ────────────────────────────────────────────────────────────
app.get("/reset-password", async (c) => {
  const url = new URL(c.req.url);
  const token = url.searchParams.get("token") || "";
  const error = url.searchParams.get("error") || "";
  const errorMsg = error === "expired" ? "This reset link has expired or already been used. Please request a new one." : error === "invalid" ? "Invalid reset link. Please request a new one." : error === "mismatch" ? "Passwords do not match." : error === "short" ? "Password must be at least 8 characters." : "";
  if (!token) return c.redirect("/forgot-password");
  return c.html(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Reset Password &#x2014; ClinicOS AI</title><style>${SHARED_STYLES}${AUTH_STYLES}</style></head><body>${buildNav(null)}
<div class="auth-wrap"><div class="auth-card">
  <div class="auth-logo"><div class="logo-icon">&#x1F510;</div><h2>Set new password</h2><p>Choose a strong password for your account</p></div>
  ${errorMsg ? `<div class="auth-error">&#x26A0;&#xFE0F; ${escHtml(errorMsg)}</div>` : ""}
  <form method="POST" action="/reset-password">
    <input type="hidden" name="token" value="${escHtml(token)}">
    <div class="form-group"><label for="password">New Password</label><input type="password" id="password" name="password" placeholder="At least 8 characters" required autocomplete="new-password" minlength="8"></div>
    <div class="form-group"><label for="confirm">Confirm Password</label><input type="password" id="confirm" name="confirm" placeholder="Repeat your new password" required autocomplete="new-password" minlength="8"></div>
    <button type="submit" class="auth-submit">Set New Password &#x2192;</button>
  </form>
  <div class="auth-footer"><a href="/login">&#x2190; Back to Sign In</a></div>
</div></div>
${FOOTER}<script>navigator.sendBeacon("/api/_ping");</script></body></html>`);
});

app.post("/reset-password", async (c) => {
  const form = await c.req.formData();
  const token = (form.get("token") as string || "").trim();
  const password = form.get("password") as string || "";
  const confirm = form.get("confirm") as string || "";
  if (!token) return c.redirect("/forgot-password");
  if (password.length < 8) return c.redirect(`/reset-password?token=${encodeURIComponent(token)}&error=short`);
  if (password !== confirm) return c.redirect(`/reset-password?token=${encodeURIComponent(token)}&error=mismatch`);
  const tokenHash = await hashToken(token);
  const now = Math.floor(Date.now() / 1000);
  const row = await c.env.DB.prepare("SELECT id, user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash = ?").bind(tokenHash).first<{ id: string; user_id: string; expires_at: number; used_at: number | null }>();
  if (!row) return c.redirect(`/reset-password?token=${encodeURIComponent(token)}&error=invalid`);
  if (row.used_at || row.expires_at < now) return c.redirect(`/reset-password?token=${encodeURIComponent(token)}&error=expired`);
  const salt = generateId();
  const hash = await hashPassword(password, salt);
  await c.env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?").bind(hash, salt, row.user_id).run();
  await c.env.DB.prepare("UPDATE password_reset_tokens SET used_at = ? WHERE id = ?").bind(now, row.id).run();
  // Invalidate all sessions for this user
  await c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(row.user_id).run().catch(() => {});
  return c.redirect("/login?reset=1");
});

// ─── My Claims ─────────────────────────────────────────────────────────────────
app.get("/my-claims", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.redirect("/login?next=/my-claims");
  const url = new URL(c.req.url);
  const reportId = url.searchParams.get("report");
  // Fetch PM connections for "Connected PM Systems" section (only in list view)
  let pmConns: Array<{ system: string; connected_at: number }> = [];
  if (!reportId) {
    const r = await c.env.DB.prepare("SELECT system, connected_at FROM pm_connections WHERE user_id = ?")
      .bind(user.user_id).all<{ system: string; connected_at: number }>();
    pmConns = r.results || [];
  }

  if (reportId) {
    // View a specific report
    const af = accountFilter(user);
    const report = await c.env.DB.prepare(
      `SELECT id, filename, total_claims, flagged_count, results_json, created_at FROM claim_reports WHERE id = ? AND (${af.clause})`
    ).bind(reportId, af.param).first<{ id: string; filename: string; total_claims: number; flagged_count: number; results_json: string; created_at: number }>();
    if (!report) return c.redirect("/my-claims");
    let results: { flagged: unknown[]; clean_rows: unknown[]; is_batch?: boolean; batch_files?: unknown[] } = { flagged: [], clean_rows: [] };
    try { results = JSON.parse(report.results_json); } catch { /**/ }
    const date = new Date(report.created_at * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
    const flagged = (results.flagged || []) as Array<Record<string, unknown>>;
    const cleanRows = (results.clean_rows || []) as Array<Record<string, unknown>>;
    const isBatchReport = !!results.is_batch;
    const hi = flagged.filter(r => r.severity === "High").length;
    const md = flagged.filter(r => r.severity === "Medium").length;
    const lo = flagged.filter(r => r.severity === "Low").length;

    const sevStyle = (sev: unknown) => sev === "High" ? "background:#fef2f2;color:#dc2626;border:1px solid #fecaca" : sev === "Medium" ? "background:#fffbeb;color:#b45309;border:1px solid #fde68a" : "background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe";
    const colSpan = isBatchReport ? 9 : 8;
    const tableRows = flagged.length === 0
      ? `<tr><td colspan="${colSpan}"><div style="text-align:center;padding:2.5rem;color:#64748b">&#x1F389; No issues found in any claims!</div></td></tr>`
      : flagged.map(row => `<tr>
          ${isBatchReport ? `<td style="font-size:.8rem;color:#475569;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(String(row.source_file ?? ""))}">${escHtml(String(row.source_file ?? "—"))}</td>` : ""}
          <td style="font-weight:600;color:#94a3b8;font-size:.8rem">${escHtml(String(row.row_number ?? ""))}</td>
          <td style="font-weight:600;color:#0f172a;font-size:.85rem">${escHtml(String(row.claim_id ?? "\u2014"))}</td>
          <td>${escHtml(String(row.patient_id ?? "\u2014"))}</td>
          <td style="white-space:nowrap">${escHtml(String(row.date_of_service ?? "\u2014"))}</td>
          <td><code style="background:#f1f5f9;padding:.15rem .5rem;border-radius:5px;font-size:.85rem;font-weight:600">${escHtml(String(row.cpt_code ?? "\u2014"))}</code></td>
          <td><div style="font-weight:600;color:#0f172a;font-size:.78rem;background:#f1f5f9;display:inline-block;padding:.15rem .5rem;border-radius:4px;margin-bottom:.35rem;border:1px solid #e2e8f0">${escHtml(String(row.issue_type ?? ""))}</div><div style="color:#475569;font-size:.84rem">${escHtml(String(row.description ?? ""))}</div></td>
          <td><span style="display:inline-flex;align-items:center;gap:.3rem;padding:.25rem .65rem;border-radius:20px;font-size:.72rem;font-weight:700;text-transform:uppercase;${sevStyle(row.severity)}">${escHtml(String(row.severity ?? ""))}</span></td>
          <td><div style="color:#0369a1;font-size:.82rem;font-style:italic">${escHtml(String(row.suggested_fix ?? "\u2014"))}</div></td>
        </tr>`).join("");

    return c.html(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Report: ${escHtml(report.filename)} &#x2014; ClinicOS AI</title>
<style>${SHARED_STYLES}body{background:#f1f5f9}
.rpt-wrap{max-width:1100px;margin:0 auto;padding:2.5rem 1.5rem 4rem}
.rpt-back{display:inline-flex;align-items:center;gap:.4rem;color:var(--electric-blue);font-weight:600;text-decoration:none;margin-bottom:1.5rem;font-size:.9rem}
.rpt-back:hover{text-decoration:underline}
.card{background:#fff;border-radius:16px;border:1px solid #e2e8f0;padding:2rem;margin-bottom:1.5rem;box-shadow:0 4px 16px rgba(0,0,0,.05)}
.summary-bar{background:linear-gradient(135deg,#0f172a,#0d2144);color:#fff;border-radius:14px;padding:1.4rem 1.75rem;display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem;box-shadow:0 4px 20px rgba(15,23,42,.25)}
.summary-stats{display:flex;gap:2rem;flex-wrap:wrap}
.summary-stat{text-align:center;min-width:48px}
.summary-stat .num{font-size:1.9rem;font-weight:800;line-height:1}
.summary-stat .lbl{font-size:.7rem;color:rgba(255,255,255,.6);text-transform:uppercase;letter-spacing:.5px;margin-top:.2rem}
.sep{width:1px;background:rgba(255,255,255,.15);align-self:stretch;margin:0 .5rem}
.table-wrap{overflow-x:auto;border-radius:12px;border:1px solid #e2e8f0}
table{width:100%;border-collapse:collapse;font-size:.875rem}
thead{background:#0f172a}
thead th{padding:.85rem 1rem;text-align:left;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px;white-space:nowrap}
tbody tr{border-bottom:1px solid #f1f5f9}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:#f8fafc}
tbody td{padding:.9rem 1rem;color:#334155;vertical-align:top;line-height:1.5}
</style></head><body>
${buildNav(user)}
<div class="rpt-wrap">
  <a href="/my-claims" class="rpt-back">&#x2190; Back to My Claims</a>
  <div style="margin-bottom:1.5rem">
    <h1 style="font-size:1.75rem;font-weight:800;color:#0f172a;margin-bottom:.4rem">&#x1F4CB; ${escHtml(report.filename)}</h1>
    <p style="color:#64748b;font-size:.9rem">Uploaded ${date}</p>
  </div>
  <div class="summary-bar">
    <div class="summary-stats">
      <div class="summary-stat"><div class="num">${flagged.length}</div><div class="lbl">Flagged</div></div>
      <div class="summary-stat"><div class="num">${report.total_claims}</div><div class="lbl">Total</div></div>
      <div class="sep"></div>
      <div class="summary-stat"><div class="num" style="color:#f87171">${hi}</div><div class="lbl">High</div></div>
      <div class="summary-stat"><div class="num" style="color:#fbbf24">${md}</div><div class="lbl">Medium</div></div>
      <div class="summary-stat"><div class="num" style="color:#60a5fa">${lo}</div><div class="lbl">Low</div></div>
      <div class="sep"></div>
      <div class="summary-stat"><div class="num" style="color:#34d399">${cleanRows.length}</div><div class="lbl">Clean</div></div>
    </div>
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <div class="table-wrap">
      <table>
        <thead><tr>${isBatchReport ? '<th>Source File</th>' : ''}<th style="width:48px">#</th><th>Claim ID</th><th>Patient ID</th><th>Date of Service</th><th>CPT</th><th>Issue Found</th><th>Severity</th><th>Suggested Fix</th></tr></thead>
        <tbody>${tableRows}</tbody>
      </table>
    </div>
  </div>
</div>
${FOOTER}<script>navigator.sendBeacon("/api/_ping");</script></body></html>`);
  }

  // List all reports
  const afList = accountFilter(user);
  const reports = await c.env.DB.prepare(
    `SELECT id, filename, total_claims, flagged_count, created_at FROM claim_reports WHERE ${afList.clause} ORDER BY created_at DESC LIMIT 50`
  ).bind(afList.param).all<{ id: string; filename: string; total_claims: number; flagged_count: number; created_at: number }>();

  const rows = (reports.results || []).map(r => {
    const date = new Date(r.created_at * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
    const flagPct = r.total_claims > 0 ? Math.round(r.flagged_count / r.total_claims * 100) : 0;
    return `<tr>
      <td style="color:#64748b;font-size:.88rem;white-space:nowrap">${escHtml(date)}</td>
      <td style="font-weight:600;color:#0f172a">${escHtml(r.filename)}</td>
      <td style="text-align:center;font-weight:700;color:#0f172a">${r.total_claims}</td>
      <td style="text-align:center"><span style="font-weight:700;color:${r.flagged_count > 0 ? "#dc2626" : "#10b981"}">${r.flagged_count}</span><span style="color:#94a3b8;font-size:.8rem;margin-left:.3rem">(${flagPct}%)</span></td>
      <td style="text-align:center"><a href="/my-claims?report=${escHtml(r.id)}" style="background:linear-gradient(135deg,#0284c7,#06b6d4);color:#fff;padding:.45rem 1rem;border-radius:6px;text-decoration:none;font-size:.85rem;font-weight:600;white-space:nowrap;display:inline-block;transition:opacity .2s" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">View Report &#x2197;</a></td>
    </tr>`;
  }).join("");

  const tableContent = rows
    ? `<div style="overflow-x:auto;border-radius:12px;border:1px solid #e2e8f0"><table style="width:100%;border-collapse:collapse;font-size:.9rem">
        <thead style="background:#0f172a"><tr>
          <th style="padding:.85rem 1rem;text-align:left;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">Date</th>
          <th style="padding:.85rem 1rem;text-align:left;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">Filename</th>
          <th style="padding:.85rem 1rem;text-align:center;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">Total Claims</th>
          <th style="padding:.85rem 1rem;text-align:center;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">Flagged</th>
          <th style="padding:.85rem 1rem;text-align:center;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">Report</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table></div>`
    : `<div style="text-align:center;padding:4rem 2rem">
        <div style="font-size:3rem;margin-bottom:1rem">&#x1F4CB;</div>
        <h3 style="font-size:1.25rem;color:#0f172a;font-weight:700;margin-bottom:.5rem">No claims uploaded yet</h3>
        <p style="color:#64748b;margin-bottom:1.5rem">Head to the Claim Scrubber to get started.</p>
        <a href="/scrubber" class="btn btn-primary">Go to Claim Scrubber &#x2192;</a>
      </div>`;

  // Fetch appeal letters for the tab
  const afAppeals = accountFilter(user);
  const appealLetters = await c.env.DB.prepare(
    `SELECT id,denial_code,denial_label,patient_id,date_of_service,cpt_code,payer_name,billed_amount,letter_text,created_at FROM appeal_letters WHERE ${afAppeals.clause} ORDER BY created_at DESC LIMIT 100`
  ).bind(afAppeals.param).all<{ id: string; denial_code: string; denial_label: string; patient_id: string; date_of_service: string; cpt_code: string; payer_name: string; billed_amount: number; letter_text: string; created_at: number }>();

  const appealLetterData: Record<string, { text: string; code: string; label: string }> = {};
  const appealRows = (appealLetters.results || []).map(r => {
    const date = new Date(r.created_at * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
    appealLetterData[r.id] = { text: r.letter_text, code: r.denial_code, label: r.denial_label };
    return `<tr>
      <td style="color:#64748b;font-size:.88rem;white-space:nowrap">${escHtml(date)}</td>
      <td><code style="background:#f1f5f9;padding:.15rem .5rem;border-radius:5px;font-size:.83rem;font-weight:700">${escHtml(r.denial_code)}</code><div style="color:#64748b;font-size:.8rem;margin-top:.2rem">${escHtml(r.denial_label)}</div></td>
      <td><code style="background:#f1f5f9;padding:.15rem .5rem;border-radius:5px;font-size:.83rem;font-weight:700">${escHtml(r.cpt_code)}</code></td>
      <td style="font-size:.88rem">${escHtml(r.payer_name)}</td>
      <td style="text-align:center"><button data-id="${escHtml(r.id)}" class="view-letter-btn" style="background:linear-gradient(135deg,#0284c7,#06b6d4);color:#fff;padding:.45rem 1rem;border-radius:6px;border:none;font-size:.85rem;font-weight:600;cursor:pointer;white-space:nowrap;transition:opacity .2s" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">View Letter &#x2197;</button></td>
    </tr>`;
  }).join("");

  const appealTableContent = appealRows
    ? `<div style="overflow-x:auto;border-radius:12px;border:1px solid #e2e8f0"><table style="width:100%;border-collapse:collapse;font-size:.9rem">
        <thead style="background:#0f172a"><tr>
          <th style="padding:.85rem 1rem;text-align:left;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">Date</th>
          <th style="padding:.85rem 1rem;text-align:left;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">Denial Code</th>
          <th style="padding:.85rem 1rem;text-align:left;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">CPT</th>
          <th style="padding:.85rem 1rem;text-align:left;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">Payer</th>
          <th style="padding:.85rem 1rem;text-align:center;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">Letter</th>
        </tr></thead>
        <tbody id="appealTbody">${appealRows}</tbody>
      </table></div>`
    : `<div style="text-align:center;padding:4rem 2rem">
        <div style="font-size:3rem;margin-bottom:1rem">&#x270D;&#xFE0F;</div>
        <h3 style="font-size:1.25rem;color:#0f172a;font-weight:700;margin-bottom:.5rem">No appeal letters yet</h3>
        <p style="color:#64748b;margin-bottom:1.5rem">Use the Appeal Generator to draft your first letter.</p>
        <a href="/appeal-generator" class="btn btn-primary">Go to Appeal Generator &#x2192;</a>
      </div>`;

  // Eligibility check history
  const afElig = accountFilter(user);
  const eligChecks = await c.env.DB.prepare(
    `SELECT id, member_id_last4, payer, cpt_code, result_status, created_at FROM eligibility_checks WHERE ${afElig.clause} ORDER BY created_at DESC LIMIT 100`
  ).bind(afElig.param).all<{ id: string; member_id_last4: string; payer: string; cpt_code: string | null; result_status: string; created_at: number }>();

  const statusLabels: Record<string, string> = {
    active: '<span style="display:inline-flex;align-items:center;gap:.3rem;padding:.2rem .65rem;border-radius:20px;font-size:.72rem;font-weight:700;background:#dcfce7;color:#166534;border:1px solid #86efac">&#x2705; Active</span>',
    unverified: '<span style="display:inline-flex;align-items:center;gap:.3rem;padding:.2rem .65rem;border-radius:20px;font-size:.72rem;font-weight:700;background:#fffbeb;color:#92400e;border:1px solid #fcd34d">&#x26A0;&#xFE0F; Unverified</span>',
    inactive: '<span style="display:inline-flex;align-items:center;gap:.3rem;padding:.2rem .65rem;border-radius:20px;font-size:.72rem;font-weight:700;background:#fef2f2;color:#991b1b;border:1px solid #fca5a5">&#x274C; Inactive</span>',
  };

  const eligRows = (eligChecks.results || []).map(r => {
    const date = new Date(r.created_at * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" });
    const badge = statusLabels[r.result_status] || statusLabels["unverified"];
    return `<tr>
      <td style="color:#64748b;font-size:.88rem;white-space:nowrap">${escHtml(date)}</td>
      <td style="font-weight:600;color:#0f172a">****${escHtml(r.member_id_last4)}</td>
      <td style="color:#0f172a">${escHtml(r.payer)}</td>
      <td style="text-align:center"><code style="background:#f1f5f9;padding:.15rem .5rem;border-radius:5px;font-size:.82rem;font-weight:600">${r.cpt_code ? escHtml(r.cpt_code) : '<span style="color:#94a3b8">—</span>'}</code></td>
      <td>${badge}</td>
    </tr>`;
  }).join("");

  const eligTableContent = eligRows
    ? `<div style="overflow-x:auto;border-radius:12px;border:1px solid #e2e8f0"><table style="width:100%;border-collapse:collapse;font-size:.9rem">
        <thead style="background:#0f172a"><tr>
          <th style="padding:.85rem 1rem;text-align:left;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">Date &amp; Time</th>
          <th style="padding:.85rem 1rem;text-align:left;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">Member ID</th>
          <th style="padding:.85rem 1rem;text-align:left;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">Payer</th>
          <th style="padding:.85rem 1rem;text-align:center;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">CPT</th>
          <th style="padding:.85rem 1rem;text-align:left;color:rgba(255,255,255,.85);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.6px">Result</th>
        </tr></thead>
        <tbody>${eligRows}</tbody>
      </table></div>`
    : `<div style="text-align:center;padding:4rem 2rem">
        <div style="font-size:3rem;margin-bottom:1rem">&#x2705;</div>
        <h3 style="font-size:1.25rem;color:#0f172a;font-weight:700;margin-bottom:.5rem">No eligibility checks yet</h3>
        <p style="color:#64748b;margin-bottom:1.5rem">Run your first check to verify patient coverage before submitting claims.</p>
        <a href="/eligibility" class="btn btn-primary">Go to Eligibility Verification &#x2192;</a>
      </div>`;

  return c.html(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>My Claims &#x2014; ClinicOS AI</title>
<style>${SHARED_STYLES}body{background:#f1f5f9}
.claims-wrap{max-width:1100px;margin:0 auto;padding:2.5rem 1.5rem 4rem}
.card{background:#fff;border-radius:16px;border:1px solid #e2e8f0;padding:2rem;box-shadow:0 4px 16px rgba(0,0,0,.05)}
tbody tr{border-bottom:1px solid #f1f5f9;transition:background .15s}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:#f8fafc}
tbody td{padding:.9rem 1rem;vertical-align:middle}
.tabs{display:flex;gap:.5rem;margin-bottom:1.5rem;border-bottom:2px solid #e2e8f0;padding-bottom:0}
.tab-btn{padding:.65rem 1.25rem;border:none;background:none;font-size:.95rem;font-weight:600;color:#64748b;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;transition:color .2s,border-color .2s}
.tab-btn.active{color:#0284c7;border-bottom-color:#0284c7}
.tab-btn:hover:not(.active){color:#0f172a}
.tab-panel{display:none}.tab-panel.active{display:block}
/* Modal */
.modal-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:9000;align-items:center;justify-content:center;padding:1rem}
.modal-backdrop.open{display:flex}
.modal{background:#fff;border-radius:16px;max-width:720px;width:100%;max-height:90vh;display:flex;flex-direction:column;overflow:hidden}
.modal-header{padding:1.25rem 1.5rem;border-bottom:1px solid #e2e8f0;display:flex;align-items:center;justify-content:space-between}
.modal-header h3{font-size:1.05rem;font-weight:700;color:#0f172a}
.modal-close{background:none;border:none;font-size:1.4rem;cursor:pointer;color:#64748b;line-height:1}
.modal-close:hover{color:#0f172a}
.modal-body{padding:1.5rem;overflow-y:auto;flex:1}
.modal-footer{padding:1rem 1.5rem;border-top:1px solid #e2e8f0;display:flex;gap:.75rem}
.letter-pre{font-family:'Courier New',Courier,monospace;font-size:.85rem;line-height:1.75;color:#1e293b;white-space:pre-wrap;background:#fafafa;border:1px solid #e2e8f0;border-radius:8px;padding:1.25rem}
</style></head><body>
${buildNav(user)}
<div class="claims-wrap">
  <div style="margin-bottom:1.5rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem">
    <div>
      <h1 style="font-size:2rem;font-weight:800;color:#0f172a;margin-bottom:.3rem">My Claims</h1>
      <p style="color:#64748b">${escHtml(user.email)}</p>
    </div>
    <div style="display:flex;gap:.75rem;flex-wrap:wrap">
      <a href="/scrubber" class="btn btn-secondary" style="padding:.65rem 1.2rem;font-size:.9rem">+ New Upload</a>
      <a href="/appeal-generator" class="btn btn-primary" style="padding:.65rem 1.2rem;font-size:.9rem">&#x270D; Generate Appeal</a>
    </div>
  </div>

  <!-- Connected PM Systems -->
  <div class="card" style="margin-bottom:1.5rem">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;flex-wrap:wrap;gap:.75rem">
      <div style="display:flex;align-items:center;gap:.5rem">
        <span style="font-size:1.2rem">&#x1F517;</span>
        <h2 style="font-size:1rem;font-weight:800;color:#0f172a">Connected PM Systems</h2>
      </div>
      <a href="/scrubber" style="font-size:.85rem;color:#0284c7;font-weight:600;text-decoration:none">Manage Connections &#x2197;</a>
    </div>
    ${['kareo','advancedmd','drchrono'].map(sys => {
      const conn = pmConns.find(pc => pc.system === sys);
      const label = sys === 'kareo' ? 'Kareo / Tebra' : sys === 'advancedmd' ? 'AdvancedMD' : 'DrChrono';
      const connDate = conn ? new Date(conn.connected_at * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : null;
      const color = sys === 'kareo' ? '#3b82f6' : sys === 'advancedmd' ? '#10b981' : '#8b5cf6';
      const initial = sys === 'kareo' ? 'K' : sys === 'advancedmd' ? 'AMD' : 'DC';
      return `<div style="display:flex;align-items:center;justify-content:space-between;padding:.85rem 1rem;background:${conn ? '#f0fdf4' : '#f8fafc'};border:1.5px solid ${conn ? '#86efac' : '#e2e8f0'};border-radius:10px;margin-bottom:.6rem;flex-wrap:wrap;gap:.6rem">
        <div style="display:flex;align-items:center;gap:.75rem">
          <div style="width:32px;height:32px;border-radius:7px;background:linear-gradient(135deg,${color},${color}cc);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:.75rem;flex-shrink:0">${initial}</div>
          <div>
            <div style="font-weight:700;color:#0f172a;font-size:.92rem">${label}</div>
            ${conn ? `<div style="color:#15803d;font-size:.78rem">Connected ${connDate}</div>` : '<div style="color:#94a3b8;font-size:.78rem">Not connected</div>'}
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:.6rem">
          ${conn ? `<span style="display:inline-flex;align-items:center;gap:.3rem;background:#dcfce7;color:#166534;border:1px solid #86efac;border-radius:20px;padding:.2rem .7rem;font-size:.72rem;font-weight:700">&#x2713; Connected</span>
          <button onclick="pmDisconnect('${sys}')" style="padding:.35rem .9rem;background:#fef2f2;color:#dc2626;border:1.5px solid #fca5a5;border-radius:7px;font-size:.8rem;font-weight:700;cursor:pointer;transition:opacity .2s" onmouseover="this.style.opacity='.7'" onmouseout="this.style.opacity='1'">Disconnect</button>` : `<span style="color:#94a3b8;font-size:.82rem">—</span>`}
        </div>
      </div>`;
    }).join('')}
    <div id="pmActionMsg" style="display:none;font-size:.87rem;margin-top:.5rem;padding:.5rem .85rem;border-radius:7px"></div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('claims',this)">&#x1F4CB; Claim Reports</button>
    <button class="tab-btn" onclick="switchTab('appeals',this)">&#x270D; Appeal Letters</button>
    <button class="tab-btn" onclick="switchTab('eligibility',this)">&#x2705; Eligibility Checks</button>
  </div>

  <div id="tab-claims" class="tab-panel active">
    <div class="card" style="${rows ? "padding:0;overflow:hidden" : ""}">${tableContent}</div>
  </div>
  <div id="tab-appeals" class="tab-panel">
    <div style="margin-bottom:1rem;display:flex;justify-content:flex-end">
      <a href="/appeal-generator" class="btn btn-primary" style="padding:.6rem 1.2rem;font-size:.88rem">+ Generate New Appeal</a>
    </div>
    <div class="card" style="${appealRows ? "padding:0;overflow:hidden" : ""}">${appealTableContent}</div>
  </div>
  <div id="tab-eligibility" class="tab-panel">
    <div style="margin-bottom:1rem;display:flex;justify-content:flex-end">
      <a href="/eligibility" class="btn btn-primary" style="padding:.6rem 1.2rem;font-size:.88rem">+ New Eligibility Check</a>
    </div>
    <div class="card" style="${eligRows ? "padding:0;overflow:hidden" : ""}">
      ${eligTableContent}
    </div>
  </div>
</div>

<!-- Letter modal -->
<div class="modal-backdrop" id="letterModal">
  <div class="modal">
    <div class="modal-header">
      <h3 id="modalTitle">Appeal Letter</h3>
      <button class="modal-close" onclick="closeModal()">&#x2715;</button>
    </div>
    <div class="modal-body">
      <pre id="modalLetterText" class="letter-pre"></pre>
    </div>
    <div class="modal-footer">
      <button onclick="copyModalLetter()" style="background:#0f172a;color:#fff;border:none;border-radius:8px;padding:.6rem 1.2rem;font-size:.88rem;font-weight:600;cursor:pointer" id="modalCopyBtn">&#x1F4CB; Copy</button>
      <button onclick="downloadModalLetter()" style="background:#f1f5f9;color:#0f172a;border:1.5px solid #e2e8f0;border-radius:8px;padding:.6rem 1.2rem;font-size:.88rem;font-weight:600;cursor:pointer">&#x2B07; Download .txt</button>
      <button onclick="closeModal()" style="margin-left:auto;background:none;border:none;color:#64748b;font-size:.9rem;cursor:pointer">Close</button>
    </div>
  </div>
</div>

${FOOTER}
<script>
function switchTab(name, btn) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
}
async function pmDisconnect(system) {
  if (!confirm('Disconnect ' + system + '? You can reconnect at any time from the Claim Scrubber page.')) return;
  try {
    const r = await fetch('/api/pm/disconnect', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({system}) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Failed to disconnect');
    location.reload();
  } catch(e) {
    const msg = document.getElementById('pmActionMsg');
    if (msg) { msg.style.display='block'; msg.style.background='#fef2f2'; msg.style.color='#dc2626'; msg.textContent = e.message || 'Disconnect failed'; }
  }
}

const _letterData = ${JSON.stringify(appealLetterData)};
let _modalText = '';
let _modalCode = '';
document.querySelectorAll('.view-letter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const id = btn.dataset.id;
    const d = _letterData[id];
    if (!d) return;
    _modalText = d.text;
    _modalCode = d.code;
    document.getElementById('modalTitle').textContent = d.code + ' — ' + d.label;
    document.getElementById('modalLetterText').textContent = d.text;
    document.getElementById('letterModal').classList.add('open');
  });
});
function closeModal() {
  document.getElementById('letterModal').classList.remove('open');
}
document.getElementById('letterModal').addEventListener('click', function(e) {
  if (e.target === this) closeModal();
});
async function copyModalLetter() {
  try {
    await navigator.clipboard.writeText(_modalText);
    const btn = document.getElementById('modalCopyBtn');
    btn.textContent = '✓ Copied!';
    setTimeout(() => { btn.textContent = '📋 Copy'; }, 2000);
  } catch(e) {}
}
function downloadModalLetter() {
  const date = new Date().toISOString().slice(0,10);
  const filename = 'appeal-' + _modalCode.replace(/[^a-z0-9]/gi,'-') + '-' + date + '.txt';
  const blob = new Blob([_modalText], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

// Open tab from query string
if (window.location.search.includes('tab=appeals')) {
  document.querySelectorAll('.tab-btn')[1].click();
} else if (window.location.search.includes('tab=eligibility')) {
  document.querySelectorAll('.tab-btn')[2].click();
}
</script>
<script>navigator.sendBeacon("/api/_ping");</script></body></html>`);
});

// ─── Checkout stubs ───────────────────────────────────────────────────────────
app.get("/checkout/success", async (c) => {
  const user = await getCurrentUser(c);
  const sessionId = new URL(c.req.url).searchParams.get("session_id");
  // Subscription gating: look up the session and update user plan
  if (sessionId && user) {
    try {
      const saleResp = await fetch(
        `${c.env.LAUNCHYARD_API_BASE_URL}/v1/public/companies/${c.env.COMPANY_ID}/sales/by-session/${sessionId}`
      );
      if (saleResp.ok) {
        const sale = await saleResp.json() as { customer_email?: string };
        if (sale.customer_email) {
          await c.env.DB.prepare("UPDATE users SET stripe_customer_id = ?, plan = ? WHERE email = ?")
            .bind(sessionId, "starter", sale.customer_email.toLowerCase()).run().catch(() => {});
        }
      }
    } catch { /**/ }
  }
  return c.html(`<!DOCTYPE html><html><head><title>Thank You &#x2014; ClinicOS AI</title><style>${SHARED_STYLES}body{background:#f8fafc}.msg{max-width:600px;margin:5rem auto;text-align:center;padding:2rem}.msg h1{font-size:2rem;color:var(--navy);margin-bottom:1rem}.msg p{color:var(--gray-dark);margin-bottom:2rem}</style></head><body>${buildNav(user)}<div class="msg"><h1>&#x2705; Thank you for your purchase!</h1><p>Your subscription is now active. You'll receive a confirmation email shortly.</p><a href="/" class="btn btn-primary">Back to Home</a></div>${FOOTER}<script>navigator.sendBeacon("/api/_ping");</script></body></html>`);
});
app.get("/checkout/cancel", async (c) => {
  const user = await getCurrentUser(c);
  return c.html(`<!DOCTYPE html><html><head><title>Checkout Cancelled &#x2014; ClinicOS AI</title><style>${SHARED_STYLES}body{background:#f8fafc}.msg{max-width:600px;margin:5rem auto;text-align:center;padding:2rem}.msg h1{font-size:2rem;color:var(--navy);margin-bottom:1rem}.msg p{color:var(--gray-dark);margin-bottom:2rem}</style></head><body>${buildNav(user)}<div class="msg"><h1>No worries, come back anytime.</h1><p>Your checkout was cancelled &#x2014; no charge was made.</p><a href="/" class="btn btn-primary">Back to Home</a></div>${FOOTER}<script>navigator.sendBeacon("/api/_ping");</script></body></html>`);
});

// ─── Appeal Generator ─────────────────────────────────────────────────────────

const APPEAL_STYLES = `
.appeal-wrap{max-width:1200px;margin:0 auto;padding:2.5rem 1.5rem 4rem}
.appeal-hero{background:linear-gradient(135deg,#0f172a 0%,#0d2144 100%);color:#fff;padding:2.5rem 2rem;margin-bottom:2rem;border-radius:16px}
.appeal-hero h1{font-size:2rem;font-weight:800;margin-bottom:.4rem}
.appeal-hero p{color:rgba(255,255,255,.75);font-size:.95rem}
.appeal-layout{display:grid;grid-template-columns:420px 1fr;gap:2rem;align-items:start}
@media(max-width:900px){.appeal-layout{grid-template-columns:1fr}}
.card{background:#fff;border-radius:16px;border:1px solid #e2e8f0;padding:1.75rem;box-shadow:0 4px 16px rgba(0,0,0,.05)}
.form-group{margin-bottom:1.2rem}
.form-group label{display:block;font-size:.85rem;font-weight:600;color:#0f172a;margin-bottom:.4rem}
.form-group input,.form-group textarea,.form-group select{width:100%;padding:.65rem .85rem;border:1.5px solid #e2e8f0;border-radius:8px;font-size:.9rem;color:#334155;background:#fff;transition:border-color .2s;font-family:inherit}
.form-group input:focus,.form-group textarea:focus,.form-group select:focus{outline:none;border-color:#0284c7;box-shadow:0 0 0 3px rgba(2,132,199,.1)}
.input-prefix{display:flex;align-items:center;border:1.5px solid #e2e8f0;border-radius:8px;overflow:hidden;transition:border-color .2s;background:#fff}
.input-prefix:focus-within{border-color:#0284c7;box-shadow:0 0 0 3px rgba(2,132,199,.1)}
.input-prefix span{padding:.65rem .75rem;background:#f8fafc;color:#64748b;font-weight:600;font-size:.9rem;border-right:1.5px solid #e2e8f0;flex-shrink:0}
.input-prefix input{border:none!important;box-shadow:none!important;border-radius:0}
.input-prefix input:focus{outline:none}
.denial-select-wrap{position:relative}
.denial-search{width:100%;padding:.65rem .85rem;border:1.5px solid #e2e8f0;border-radius:8px;font-size:.9rem;color:#334155;background:#fff;cursor:pointer}
.denial-search:focus{outline:none;border-color:#0284c7;box-shadow:0 0 0 3px rgba(2,132,199,.1)}
.denial-dropdown{display:none;position:absolute;top:calc(100% + 4px);left:0;right:0;background:#fff;border:1.5px solid #e2e8f0;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.12);z-index:200;max-height:260px;overflow-y:auto}
.denial-dropdown.open{display:block}
.denial-item{padding:.6rem .85rem;cursor:pointer;font-size:.88rem;color:#334155;transition:background .1s;border-radius:6px;margin:2px}
.denial-item:hover,.denial-item.active{background:#f0f9ff;color:#0284c7}
.denial-item .code{font-weight:700;color:#0f172a;font-family:monospace;font-size:.83rem}
.denial-item.active .code{color:#0284c7}
.btn-generate{width:100%;padding:.85rem;background:linear-gradient(135deg,#0284c7,#06b6d4);color:#fff;border:none;border-radius:10px;font-size:1rem;font-weight:700;cursor:pointer;transition:all .2s;margin-top:.5rem;display:flex;align-items:center;justify-content:center;gap:.5rem}
.btn-generate:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 8px 20px rgba(2,132,199,.35)}
.btn-generate:disabled{opacity:.7;cursor:not-allowed;transform:none}
.letter-box{font-family:'Courier New',Courier,monospace;font-size:.88rem;line-height:1.75;color:#1e293b;white-space:pre-wrap;background:#fafafa;border:1px solid #e2e8f0;border-radius:10px;padding:1.5rem;min-height:400px;max-height:70vh;overflow-y:auto}
.letter-actions{display:flex;gap:.75rem;margin-top:1rem;flex-wrap:wrap}
.btn-action{padding:.6rem 1.25rem;border-radius:8px;font-size:.9rem;font-weight:600;cursor:pointer;transition:all .2s;border:none;display:inline-flex;align-items:center;gap:.4rem}
.btn-copy{background:#0f172a;color:#fff}
.btn-copy:hover{background:#1e293b}
.btn-download{background:#f1f5f9;color:#0f172a;border:1.5px solid #e2e8f0}
.btn-download:hover{background:#e2e8f0}
.preview-overlay{position:relative;margin-top:1rem}
.preview-blur{filter:blur(4px);user-select:none;pointer-events:none}
.upgrade-card{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;background:linear-gradient(to bottom,rgba(255,255,255,0) 0%,rgba(255,255,255,.97) 30%)}
.upgrade-inner{background:#fff;border:2px solid #e2e8f0;border-radius:14px;padding:2rem 1.75rem;text-align:center;max-width:380px;box-shadow:0 8px 32px rgba(0,0,0,.1)}
.upgrade-inner h3{font-size:1.1rem;font-weight:700;color:#0f172a;margin-bottom:.5rem}
.upgrade-inner p{font-size:.9rem;color:#64748b;margin-bottom:1.25rem}
.letter-placeholder{text-align:center;padding:4rem 2rem;color:#94a3b8}
.letter-placeholder .icon{font-size:3rem;margin-bottom:1rem}
.letter-placeholder p{font-size:.95rem}
.spinner{width:18px;height:18px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.error-msg{background:#fef2f2;border:1px solid #fecaca;color:#dc2626;border-radius:8px;padding:.75rem 1rem;font-size:.9rem;margin-top:.75rem}
`;

// ─── Denial Tracker ───────────────────────────────────────────────────────────

const DENIAL_TRACKER_CODES: Array<{ code: string; label: string }> = [
  { code: "CO-4",   label: "Procedure not covered" },
  { code: "CO-11",  label: "Diagnosis inconsistent with procedure" },
  { code: "CO-16",  label: "Claim lacks info" },
  { code: "CO-22",  label: "Coordination of benefits" },
  { code: "CO-29",  label: "Time limit expired" },
  { code: "CO-45",  label: "Charge exceeds fee schedule" },
  { code: "CO-97",  label: "Payment included in another service" },
  { code: "CO-109", label: "Claim not covered by payer" },
  { code: "CO-167", label: "Diagnosis not covered" },
  { code: "PR-1",   label: "Deductible" },
  { code: "PR-2",   label: "Coinsurance" },
  { code: "PR-3",   label: "Copay" },
  { code: "PR-96",  label: "Non-covered charge" },
  { code: "N30",    label: "Missing/incorrect claim data" },
  { code: "N115",   label: "Authorization required" },
  { code: "OA-23",  label: "Payment adjusted — impact of prior payer(s)" },
];

const PAYER_SUGGESTIONS = ["Medicare", "Medicaid", "Blue Cross Blue Shield", "United Healthcare", "Aetna", "Cigna", "Humana", "Other"];

app.post("/api/denials", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  if (isReadOnly(user)) return c.json({ error: "View only — contact your Admin to request access" }, 403);
  let body: any;
  try { body = await c.req.json(); } catch { return c.json({ error: "Invalid JSON" }, 400); }
  const { payer, cpt_code, denial_reason_code, date_of_service, claim_amount, notes } = body;
  if (!payer || !cpt_code || !denial_reason_code || !date_of_service || claim_amount == null)
    return c.json({ error: "Missing required fields" }, 400);
  const found = DENIAL_TRACKER_CODES.find(d => d.code === denial_reason_code);
  const denial_reason_label = found?.label || denial_reason_code;
  const id = generateId();
  await c.env.DB.prepare(
    `INSERT INTO denials (id, user_id, payer, cpt_code, denial_reason_code, denial_reason_label, date_of_service, claim_amount, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, user.user_id, payer, cpt_code, denial_reason_code, denial_reason_label, date_of_service, parseFloat(claim_amount), notes || null).run();
  return c.json({ success: true, id });
});

app.get("/denial-tracker", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.redirect("/login?next=/denial-tracker");

  // Access level for gating
  const accessLevel = await getUserAccessLevel(c.env.DB, user.user_id);
  const hasBenchmarkAccess = accessLevel === 'paid' || accessLevel === 'trial_active';

  // Load all user denials
  const afDenials = accountFilter(user);
  const denials = await c.env.DB.prepare(
    `SELECT * FROM denials WHERE ${afDenials.clause} ORDER BY created_at DESC`
  ).bind(afDenials.param).all<{
    id: string; payer: string; cpt_code: string; denial_reason_code: string;
    denial_reason_label: string; date_of_service: string; claim_amount: number;
    notes: string | null; created_at: number;
  }>();

  const rows = denials.results ?? [];

  // Current month stats
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
  const monthStartTs = Math.floor(monthStart.getTime() / 1000);
  const thisMonth = rows.filter(r => r.created_at >= monthStartTs);

  // ── Benchmarking data ────────────────────────────────────────────────────

  // Claims scrubbed per month from claim_reports
  const afClaims2 = accountFilter(user);
  const claimReports = await c.env.DB.prepare(
    `SELECT total_claims, created_at FROM claim_reports WHERE ${afClaims2.clause}`
  ).bind(afClaims2.param).all<{ total_claims: number; created_at: number }>();
  const reportRows = claimReports.results ?? [];

  // Helper: get month boundaries
  function monthBounds(year: number, month: number): { start: number; end: number } {
    const start = Math.floor(new Date(year, month, 1).getTime() / 1000);
    const end = Math.floor(new Date(year, month + 1, 1).getTime() / 1000);
    return { start, end };
  }

  // Current month claims scrubbed
  const { start: curStart, end: curEnd } = monthBounds(now.getFullYear(), now.getMonth());
  const claimsThisMonth = reportRows
    .filter(r => r.created_at >= curStart && r.created_at < curEnd)
    .reduce((sum, r) => sum + r.total_claims, 0);
  const denialsThisMonthCount = thisMonth.length;

  let denialRatePct: number | null = null;
  if (claimsThisMonth > 0) {
    denialRatePct = (denialsThisMonthCount / claimsThisMonth) * 100;
  }

  // Status indicator
  let benchStatusColor = '#94a3b8';
  let benchStatusLabel = 'No data yet';
  let benchStatusBg = '#f1f5f9';
  if (denialRatePct !== null) {
    if (denialRatePct < 10) {
      benchStatusColor = '#16a34a'; benchStatusLabel = 'Below Average'; benchStatusBg = '#f0fdf4';
    } else if (denialRatePct <= 20) {
      benchStatusColor = '#d97706'; benchStatusLabel = 'At Average'; benchStatusBg = '#fffbeb';
    } else {
      benchStatusColor = '#dc2626'; benchStatusLabel = 'Above Average'; benchStatusBg = '#fef2f2';
    }
  }

  // Top denial driver (last 30 days)
  const thirtyDaysAgo = Math.floor(Date.now() / 1000) - 30 * 86400;
  const recentDenials = rows.filter(r => r.created_at >= thirtyDaysAgo);
  const codeCountMap = new Map<string, { count: number; totalAmount: number; label: string }>();
  for (const d of recentDenials) {
    const existing = codeCountMap.get(d.denial_reason_code) || { count: 0, totalAmount: 0, label: d.denial_reason_label };
    codeCountMap.set(d.denial_reason_code, {
      count: existing.count + 1,
      totalAmount: existing.totalAmount + d.claim_amount,
      label: d.denial_reason_label || d.denial_reason_code,
    });
  }
  let topDriverCode = '';
  let topDriverLabel = '';
  let topDriverRecovery = 0;
  if (codeCountMap.size > 0) {
    const top = [...codeCountMap.entries()].sort((a, b) => b[1].count - a[1].count)[0];
    topDriverCode = top[0];
    topDriverLabel = top[1].label;
    const avgAmount = top[1].totalAmount / top[1].count;
    // This month count for that code
    const thisMonthCodeCount = thisMonth.filter(d => d.denial_reason_code === topDriverCode).length;
    topDriverRecovery = thisMonthCodeCount * avgAmount;
  }

  // 3-month trend data
  interface MonthRate { label: string; rate: number | null; denials: number; claims: number; }
  const trendMonths: MonthRate[] = [];
  for (let i = 2; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const { start, end } = monthBounds(d.getFullYear(), d.getMonth());
    const mDenials = rows.filter(r => r.created_at >= start && r.created_at < end).length;
    const mClaims = reportRows.filter(r => r.created_at >= start && r.created_at < end)
      .reduce((sum, r) => sum + r.total_claims, 0);
    const rate = mClaims > 0 ? (mDenials / mClaims) * 100 : null;
    trendMonths.push({
      label: d.toLocaleString('en-US', { month: 'short', year: '2-digit' }),
      rate, denials: mDenials, claims: mClaims,
    });
  }
  const hasEnoughTrendData = trendMonths.filter(m => m.rate !== null).length >= 2;

  // Build SVG line chart for trend
  const svgWidth = 480; const svgHeight = 160; const padL = 48; const padR = 20; const padT = 16; const padB = 36;
  const chartW = svgWidth - padL - padR;
  const chartH = svgHeight - padT - padB;
  const maxRate = Math.max(...trendMonths.map(m => m.rate ?? 0), 25);

  function rateToY(rate: number): number {
    return padT + chartH - (rate / maxRate) * chartH;
  }
  function idxToX(i: number): number {
    return padL + (i / (trendMonths.length - 1)) * chartW;
  }

  // Data points (only non-null)
  const validPoints = trendMonths.map((m, i) => m.rate !== null ? { x: idxToX(i), y: rateToY(m.rate), rate: m.rate } : null);
  const linePath = validPoints.filter(Boolean).map((p, idx) => `${idx === 0 ? 'M' : 'L'}${p!.x.toFixed(1)},${p!.y.toFixed(1)}`).join(' ');
  const bench10Y = rateToY(10);
  const bench20Y = rateToY(20);

  const trendSvg = `<svg viewBox="0 0 ${svgWidth} ${svgHeight}" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto;overflow:visible">
  <!-- grid lines -->
  ${[0,5,10,15,20,25].filter(v => v <= maxRate + 2).map(v => {
    const y = rateToY(v);
    return `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${svgWidth - padR}" y2="${y.toFixed(1)}" stroke="#e2e8f0" stroke-width="1"/>
    <text x="${padL - 6}" y="${(y + 4).toFixed(1)}" text-anchor="end" font-size="10" fill="#94a3b8">${v}%</text>`;
  }).join('')}
  <!-- bench 10% dashed -->
  <line x1="${padL}" y1="${bench10Y.toFixed(1)}" x2="${svgWidth - padR}" y2="${bench10Y.toFixed(1)}" stroke="#16a34a" stroke-width="1.5" stroke-dasharray="5,4"/>
  <text x="${svgWidth - padR + 4}" y="${(bench10Y + 4).toFixed(1)}" font-size="9" fill="#16a34a" font-weight="600">Well-run</text>
  <!-- bench 20% dashed -->
  <line x1="${padL}" y1="${bench20Y.toFixed(1)}" x2="${svgWidth - padR}" y2="${bench20Y.toFixed(1)}" stroke="#d97706" stroke-width="1.5" stroke-dasharray="5,4"/>
  <text x="${svgWidth - padR + 4}" y="${(bench20Y + 4).toFixed(1)}" font-size="9" fill="#d97706" font-weight="600">Avg</text>
  <!-- data line -->
  ${linePath ? `<path d="${linePath}" fill="none" stroke="#3b82f6" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>` : ''}
  <!-- data points -->
  ${validPoints.filter(Boolean).map(p => `<circle cx="${p!.x.toFixed(1)}" cy="${p!.y.toFixed(1)}" r="4" fill="#3b82f6" stroke="#fff" stroke-width="2"/>
  <text x="${p!.x.toFixed(1)}" y="${(p!.y - 9).toFixed(1)}" text-anchor="middle" font-size="10" font-weight="700" fill="#1e40af">${p!.rate.toFixed(1)}%</text>`).join('')}
  <!-- x axis labels -->
  ${trendMonths.map((m, i) => `<text x="${idxToX(i).toFixed(1)}" y="${svgHeight - 6}" text-anchor="middle" font-size="11" fill="#64748b">${escHtml(m.label)}</text>`).join('')}
</svg>`;

  // Build benchmarking card HTML
  const rateDisplay = denialRatePct !== null ? denialRatePct.toFixed(1) + '%' : '—';
  const recoveryDisplay = topDriverRecovery > 0 ? '$' + topDriverRecovery.toFixed(0) : '$0';

  const topDriverLine = topDriverCode
    ? `Your top denial driver is <strong>${escHtml(topDriverCode)} — ${escHtml(topDriverLabel)}</strong> — fixing this alone could recover an estimated <strong>${recoveryDisplay}/month</strong>`
    : `Log your first denial to see your top driver`;

  const benchmarkCardHtml = `
<div class="bench-card" id="benchmarkCard">
  <div class="bench-header">
    <div style="display:flex;align-items:center;gap:.6rem;flex-wrap:wrap">
      <h2 class="bench-title">Benchmarking</h2>
      <span class="bench-badge">Powered by CMS &amp; MGMA data</span>
    </div>
  </div>
  <div class="bench-body">
    <!-- Rate + status -->
    <div class="bench-rate-row">
      <div class="bench-rate-block">
        <div class="bench-rate-label">Your denial rate this month</div>
        <div class="bench-rate-value">${escHtml(rateDisplay)}</div>
        ${claimsThisMonth === 0 ? `<div class="bench-no-data">Upload claims to see your rate</div>` : ''}
      </div>
      <div class="bench-status-pill" style="background:${benchStatusBg};color:${benchStatusColor};border:1.5px solid ${benchStatusColor}30">
        <span class="bench-status-dot" style="background:${benchStatusColor}"></span>
        ${escHtml(benchStatusLabel)}
      </div>
    </div>

    <!-- Industry benchmarks -->
    <div class="bench-ranges">
      <div class="bench-range-item">
        <span class="bench-range-icon" style="color:#16a34a">&#x2713;</span>
        <span><strong>Well-run practices:</strong> 5–10%</span>
      </div>
      <div class="bench-range-item">
        <span class="bench-range-icon" style="color:#d97706">&#x2248;</span>
        <span><strong>Industry average (independent clinics):</strong> 15–20%</span>
      </div>
      <div class="bench-source">Source: CMS &amp; MGMA published data</div>
    </div>

    <!-- Top driver -->
    <div class="bench-driver">
      <span class="bench-driver-icon">&#x1F4A1;</span>
      <span>${topDriverLine}</span>
    </div>
  </div>
</div>

<!-- How you compare -->
<div class="bench-trend-card">
  <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:1rem;flex-wrap:wrap">
    <h2 class="bench-title" style="margin:0">How You Compare</h2>
    <span style="font-size:.78rem;color:#94a3b8">Denial rate — last 3 months</span>
  </div>
  ${hasEnoughTrendData
    ? `<div class="bench-chart-wrap">${trendSvg}</div>`
    : `<div class="bench-no-trend">&#x1F4CA; Keep using ClinicOS — your trend will appear here after a few months of data.</div>`
  }
  <div style="margin-top:.75rem;display:flex;gap:1.25rem;flex-wrap:wrap">
    <span style="font-size:.78rem;color:#16a34a;display:flex;align-items:center;gap:.3rem"><svg width="18" height="4"><line x1="0" y1="2" x2="18" y2="2" stroke="#16a34a" stroke-width="2" stroke-dasharray="4,3"/></svg> Well-run benchmark (10%)</span>
    <span style="font-size:.78rem;color:#d97706;display:flex;align-items:center;gap:.3rem"><svg width="18" height="4"><line x1="0" y1="2" x2="18" y2="2" stroke="#d97706" stroke-width="2" stroke-dasharray="4,3"/></svg> Industry average (20%)</span>
  </div>
</div>

<!-- Share report -->
<div style="margin-bottom:2rem;text-align:right">
  <button class="btn-share" id="shareReportBtn" onclick="shareReport()">&#x1F4CB; Share Report</button>
  <span id="copiedMsg" style="display:none;margin-left:.75rem;color:#16a34a;font-size:.88rem;font-weight:600">Copied!</span>
</div>`;

  // Share report text (injected into JS)
  const trendLinesForShare = trendMonths.map(m =>
    `${m.label}: ${m.rate !== null ? m.rate.toFixed(1) + '%' : 'N/A'}`
  ).join('\n');
  const shareText = `ClinicOS AI — Denial Rate Report
Generated: ${now.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}

Practice Denial Rate (this month): ${denialRatePct !== null ? denialRatePct.toFixed(1) + '%' : 'N/A'}
Industry Benchmark: 5–10% (well-run) / 15–20% (average)
Status: ${benchStatusLabel}

Top Denial Driver: ${topDriverCode ? topDriverCode + ' — ' + topDriverLabel : 'N/A'}
Estimated Monthly Recovery Opportunity: ${recoveryDisplay}

Trend:
${trendLinesForShare}

Source: CMS & MGMA published benchmarks. ClinicOS AI platform data.`;

  const countBy = <T extends string>(items: T[]): Array<[T, number]> => {
    const map = new Map<T, number>();
    for (const v of items) map.set(v, (map.get(v) || 0) + 1);
    return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);
  };

  const topReasons = countBy(thisMonth.map(r => r.denial_reason_code as string));
  const topPayers = countBy(thisMonth.map(r => r.payer as string));
  const topCpts = countBy(thisMonth.map(r => r.cpt_code as string));

  // 6-month trend
  const trend: Array<{ label: string; count: number }> = [];
  for (let i = 5; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const start = Math.floor(d.getTime() / 1000);
    const end = Math.floor(new Date(d.getFullYear(), d.getMonth() + 1, 1).getTime() / 1000);
    const cnt = rows.filter(r => r.created_at >= start && r.created_at < end).length;
    trend.push({ label: d.toLocaleString("en-US", { month: "short", year: "2-digit" }), count: cnt });
  }
  const maxTrend = Math.max(...trend.map(t => t.count), 1);

  const codeOptions = DENIAL_TRACKER_CODES.map(d =>
    `<option value="${escHtml(d.code)}">${escHtml(d.code)} — ${escHtml(d.label)}</option>`
  ).join("");

  const payerDatalist = PAYER_SUGGESTIONS.map(p => `<option value="${escHtml(p)}">`).join("");

  const summaryReasons = topReasons.length
    ? topReasons.map(([code, cnt]) => {
        const lbl = DENIAL_TRACKER_CODES.find(d => d.code === code)?.label || code;
        return `<div class="summary-item"><span class="summary-badge">${escHtml(code)}</span><span class="summary-desc">${escHtml(lbl)}</span><span class="summary-count">${cnt}</span></div>`;
      }).join("")
    : `<div class="summary-empty">No denials this month</div>`;

  const summaryPayers = topPayers.length
    ? topPayers.map(([p, cnt]) => `<div class="summary-item"><span class="summary-desc">${escHtml(p)}</span><span class="summary-count">${cnt}</span></div>`).join("")
    : `<div class="summary-empty">No denials this month</div>`;

  const summaryCpts = topCpts.length
    ? topCpts.map(([c, cnt]) => `<div class="summary-item"><span class="summary-badge">${escHtml(c)}</span><span class="summary-count">${cnt}</span></div>`).join("")
    : `<div class="summary-empty">No denials this month</div>`;

  const tableRows = rows.length
    ? rows.map(r => {
        const appealUrl = `/appeal-generator?denial_code=${encodeURIComponent(r.denial_reason_code)}&cpt=${encodeURIComponent(r.cpt_code)}&payer=${encodeURIComponent(r.payer)}&date=${encodeURIComponent(r.date_of_service)}&amount=${encodeURIComponent(r.claim_amount)}`;
        const amount = `$${r.claim_amount.toFixed(2)}`;
        return `<tr>
          <td>${escHtml(r.date_of_service)}</td>
          <td>${escHtml(r.payer)}</td>
          <td><code>${escHtml(r.cpt_code)}</code></td>
          <td><span class="reason-badge">${escHtml(r.denial_reason_code)}</span> <span class="reason-label">${escHtml(r.denial_reason_label)}</span></td>
          <td>${escHtml(amount)}</td>
          <td><a href="${escHtml(appealUrl)}" class="btn-appeal">Generate Appeal &#x2197;</a></td>
        </tr>`;
      }).join("")
    : `<tr><td colspan="6" class="table-empty">No denials logged yet — add your first one below.</td></tr>`;

  const trendBars = trend.map(t => {
    const pct = Math.round((t.count / maxTrend) * 100);
    return `<div class="trend-col">
      <div class="trend-bar-wrap"><div class="trend-bar" style="height:${pct}%"></div></div>
      <div class="trend-count">${t.count}</div>
      <div class="trend-label">${escHtml(t.label)}</div>
    </div>`;
  }).join("");

  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Denial Tracker — ClinicOS AI</title>
<style>
${SHARED_STYLES}
body{background:#f1f5f9}
.dt-wrap{max-width:1100px;margin:0 auto;padding:2rem 1.5rem}
.dt-hero{margin-bottom:2rem}
.dt-hero h1{font-size:2rem;font-weight:800;color:var(--navy);margin-bottom:.4rem}
.dt-hero p{color:var(--gray-dark);font-size:1rem}
.summary-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1.25rem;margin-bottom:2rem}
@media(max-width:700px){.summary-grid{grid-template-columns:1fr}}
.summary-card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:1.25rem;box-shadow:0 2px 8px rgba(0,0,0,.04)}
.summary-card h3{font-size:.85rem;font-weight:700;color:var(--gray-dark);text-transform:uppercase;letter-spacing:.05em;margin-bottom:1rem}
.summary-item{display:flex;align-items:center;gap:.5rem;padding:.4rem 0;border-bottom:1px solid #f1f5f9}
.summary-item:last-child{border-bottom:none}
.summary-badge{background:#eff6ff;color:#1d4ed8;border-radius:6px;padding:.15rem .5rem;font-size:.78rem;font-weight:700;white-space:nowrap}
.summary-desc{flex:1;font-size:.88rem;color:var(--navy);font-weight:500}
.summary-count{background:#f0fdf4;color:#15803d;border-radius:20px;padding:.15rem .6rem;font-size:.8rem;font-weight:700;white-space:nowrap}
.summary-empty{color:#94a3b8;font-size:.88rem;text-align:center;padding:.5rem 0}
.trend-card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:1.5rem;margin-bottom:2rem;box-shadow:0 2px 8px rgba(0,0,0,.04)}
.trend-card h3{font-size:.85rem;font-weight:700;color:var(--gray-dark);text-transform:uppercase;letter-spacing:.05em;margin-bottom:1.25rem}
.trend-chart{display:flex;align-items:flex-end;gap:.75rem;height:120px}
.trend-col{display:flex;flex-direction:column;align-items:center;flex:1;height:100%}
.trend-bar-wrap{flex:1;width:100%;display:flex;align-items:flex-end;justify-content:center}
.trend-bar{width:70%;background:linear-gradient(180deg,var(--electric-blue),var(--electric-teal));border-radius:4px 4px 0 0;min-height:4px;transition:height .3s}
.trend-count{font-size:.78rem;font-weight:700;color:var(--navy);margin-top:.3rem}
.trend-label{font-size:.72rem;color:var(--gray-dark);margin-top:.15rem}
.section-card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:1.5rem;margin-bottom:2rem;box-shadow:0 2px 8px rgba(0,0,0,.04)}
.section-card h2{font-size:1.1rem;font-weight:700;color:var(--navy);margin-bottom:1.25rem}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
@media(max-width:600px){.form-row{grid-template-columns:1fr}}
.form-group{margin-bottom:1rem}
.form-group label{display:block;font-size:.88rem;font-weight:600;color:var(--navy);margin-bottom:.4rem}
.form-group input,.form-group select,.form-group textarea{width:100%;padding:.6rem .85rem;border:1.5px solid #e2e8f0;border-radius:8px;font-size:.9rem;color:var(--navy);background:#fff;font-family:inherit;box-sizing:border-box;transition:border-color .2s}
.form-group input:focus,.form-group select:focus,.form-group textarea:focus{outline:none;border-color:var(--electric-blue)}
.input-prefix{display:flex;align-items:center;border:1.5px solid #e2e8f0;border-radius:8px;overflow:hidden;transition:border-color .2s;background:#fff}
.input-prefix:focus-within{border-color:var(--electric-blue)}
.input-prefix span{padding:.6rem .75rem;background:#f8fafc;color:var(--gray-dark);font-size:.9rem;font-weight:600;border-right:1.5px solid #e2e8f0}
.input-prefix input{border:none;border-radius:0;flex:1}
.input-prefix input:focus{outline:none}
.denial-select-wrap{position:relative}
.denial-dropdown{display:none;position:absolute;top:calc(100% + 4px);left:0;right:0;background:#fff;border:1.5px solid #e2e8f0;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.1);max-height:220px;overflow-y:auto;z-index:100}
.denial-dropdown.open{display:block}
.denial-item{padding:.5rem .85rem;cursor:pointer;font-size:.88rem;color:var(--navy);transition:background .15s}
.denial-item:hover,.denial-item.active{background:#eff6ff;color:#1d4ed8}
.denial-item .code{font-weight:700}
.btn-submit{background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));color:#fff;border:none;border-radius:8px;padding:.75rem 1.75rem;font-size:.95rem;font-weight:700;cursor:pointer;font-family:inherit;transition:opacity .2s,transform .2s}
.btn-submit:hover{opacity:.92;transform:translateY(-1px)}
.btn-submit:disabled{opacity:.6;cursor:not-allowed;transform:none}
.form-error{background:#fef2f2;border:1px solid #fecaca;color:#dc2626;border-radius:8px;padding:.6rem 1rem;font-size:.88rem;margin-top:.75rem;display:none}
.form-success{background:#f0fdf4;border:1px solid #bbf7d0;color:#166534;border-radius:8px;padding:.6rem 1rem;font-size:.88rem;margin-top:.75rem;display:none}
.denials-table{width:100%;border-collapse:collapse;font-size:.88rem}
.denials-table th{text-align:left;padding:.65rem .85rem;font-size:.78rem;font-weight:700;color:var(--gray-dark);text-transform:uppercase;letter-spacing:.04em;border-bottom:2px solid #e2e8f0;background:#f8fafc}
.denials-table td{padding:.7rem .85rem;border-bottom:1px solid #f1f5f9;color:var(--navy);vertical-align:middle}
.denials-table tr:last-child td{border-bottom:none}
.denials-table tr:hover td{background:#f8fafc}
.reason-badge{background:#eff6ff;color:#1d4ed8;border-radius:5px;padding:.15rem .45rem;font-size:.78rem;font-weight:700}
.reason-label{color:var(--gray-dark);font-size:.83rem}
.table-empty{text-align:center;color:#94a3b8;padding:2rem!important}
.btn-appeal{background:linear-gradient(135deg,#7c3aed,#6366f1);color:#fff;border-radius:6px;padding:.35rem .85rem;font-size:.8rem;font-weight:700;text-decoration:none;white-space:nowrap;transition:opacity .2s}
.btn-appeal:hover{opacity:.88}
.table-wrap{overflow-x:auto}
code{background:#f1f5f9;padding:.1rem .4rem;border-radius:4px;font-size:.85rem;font-family:monospace}
/* ── Benchmarking ── */
.bench-card{background:#fff;border:1.5px solid #bfdbfe;border-radius:14px;padding:1.5rem;margin-bottom:1.25rem;box-shadow:0 2px 12px rgba(59,130,246,.07)}
.bench-trend-card{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:1.5rem;margin-bottom:1.25rem;box-shadow:0 2px 8px rgba(0,0,0,.04)}
.bench-header{margin-bottom:1.1rem}
.bench-title{font-size:1.05rem;font-weight:800;color:var(--navy);margin:0}
.bench-badge{background:#eff6ff;color:#2563eb;border:1px solid #bfdbfe;border-radius:20px;padding:.2rem .7rem;font-size:.72rem;font-weight:700;letter-spacing:.02em;white-space:nowrap}
.bench-body{display:flex;flex-direction:column;gap:1rem}
.bench-rate-row{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem}
.bench-rate-block{}
.bench-rate-label{font-size:.8rem;color:#64748b;font-weight:500;margin-bottom:.2rem}
.bench-rate-value{font-size:2.25rem;font-weight:800;color:var(--navy);line-height:1}
.bench-no-data{font-size:.78rem;color:#94a3b8;margin-top:.3rem}
.bench-status-pill{display:inline-flex;align-items:center;gap:.4rem;padding:.4rem 1rem;border-radius:99px;font-size:.88rem;font-weight:700}
.bench-status-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.bench-ranges{background:#f8fafc;border-radius:10px;padding:.85rem 1rem;display:flex;flex-direction:column;gap:.45rem}
.bench-range-item{display:flex;align-items:center;gap:.5rem;font-size:.88rem;color:var(--navy)}
.bench-range-icon{font-size:1rem;width:1.2rem;text-align:center}
.bench-source{font-size:.73rem;color:#94a3b8;margin-top:.25rem}
.bench-driver{background:#f0f9ff;border:1px solid #bae6fd;border-radius:8px;padding:.75rem 1rem;font-size:.88rem;color:#0c4a6e;display:flex;align-items:flex-start;gap:.5rem;line-height:1.5}
.bench-driver-icon{font-size:1.1rem;flex-shrink:0;margin-top:.05rem}
.bench-chart-wrap{padding:.25rem 0}
.bench-no-trend{background:#f8fafc;border-radius:10px;padding:1.5rem;text-align:center;color:#64748b;font-size:.9rem}
.bench-locked{position:relative;border-radius:14px;overflow:hidden}
.bench-blur{filter:blur(6px);pointer-events:none;user-select:none}
.bench-gate{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;background:rgba(255,255,255,.75);backdrop-filter:blur(2px);padding:2rem;text-align:center;gap:.75rem}
.bench-gate h3{font-size:1rem;font-weight:700;color:var(--navy);margin:0}
.bench-gate p{font-size:.88rem;color:#64748b;margin:0}
.btn-share{background:#fff;border:1.5px solid #e2e8f0;border-radius:8px;padding:.55rem 1.1rem;font-size:.88rem;font-weight:600;color:var(--navy);cursor:pointer;transition:border-color .2s,box-shadow .2s;font-family:inherit}
.btn-share:hover{border-color:#93c5fd;box-shadow:0 2px 8px rgba(59,130,246,.12)}
</style>
</head>
<body>
${buildNav(user)}
<div class="dt-wrap">
  <div class="dt-hero">
    <h1>&#x1F6AB; Denial Tracker</h1>
    <p>Track claim denials, spot patterns, and generate appeals — all in one place.</p>
  </div>

  ${hasBenchmarkAccess
    ? benchmarkCardHtml
    : `<div class="bench-locked" style="margin-bottom:1.25rem">
        <div class="bench-blur">${benchmarkCardHtml}</div>
        <div class="bench-gate">
          <div style="font-size:2rem">&#x1F512;</div>
          <h3>See your denial rate benchmarks</h3>
          <p>Start your 14-day free trial to see how your practice compares to CMS &amp; MGMA industry benchmarks.</p>
          <a href="/signup" class="btn btn-primary" style="padding:.65rem 1.5rem;font-size:.9rem;display:inline-block;margin-top:.25rem">Start your 14-day free trial &#x2197;</a>
        </div>
      </div>`
  }

  <!-- Summary cards -->
  <div class="summary-grid">
    <div class="summary-card">
      <h3>Top Denial Reasons <span style="font-size:.75rem;color:#94a3b8">(this month)</span></h3>
      ${summaryReasons}
    </div>
    <div class="summary-card">
      <h3>Top Denying Payers <span style="font-size:.75rem;color:#94a3b8">(this month)</span></h3>
      ${summaryPayers}
    </div>
    <div class="summary-card">
      <h3>Top Flagged CPTs <span style="font-size:.75rem;color:#94a3b8">(this month)</span></h3>
      ${summaryCpts}
    </div>
  </div>

  <!-- Monthly trend -->
  <div class="trend-card">
    <h3>Monthly Denial Volume — Last 6 Months</h3>
    <div class="trend-chart">
      ${trendBars}
    </div>
  </div>

  <!-- Log form -->
  <div class="section-card">
    <h2>Log a New Denial</h2>
    <form id="denialForm">
      <div class="form-row">
        <div class="form-group">
          <label>Payer *</label>
          <input type="text" id="payer" list="payer-suggestions" placeholder="e.g. Medicare" required autocomplete="off" />
          <datalist id="payer-suggestions">${payerDatalist}</datalist>
        </div>
        <div class="form-group">
          <label>CPT Code *</label>
          <input type="text" id="cptCode" placeholder="e.g. 99213" required />
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label>Denial Reason Code *</label>
          <div class="denial-select-wrap">
            <input type="text" id="denialSearch" class="denial-search"
              placeholder="Search denial code…" autocomplete="off" />
            <input type="hidden" id="denialCode" required />
            <div class="denial-dropdown" id="denialDropdown">
              ${DENIAL_TRACKER_CODES.map(d =>
                `<div class="denial-item" data-code="${escHtml(d.code)}" data-label="${escHtml(d.label)}"><span class="code">${escHtml(d.code)}</span> — ${escHtml(d.label)}</div>`
              ).join("")}
            </div>
          </div>
        </div>
        <div class="form-group">
          <label>Date of Service *</label>
          <input type="date" id="dateOfService" required />
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label>Claim Amount *</label>
          <div class="input-prefix">
            <span>$</span>
            <input type="number" id="claimAmount" placeholder="0.00" step="0.01" min="0" required />
          </div>
        </div>
        <div class="form-group">
          <label>Notes <span style="color:#94a3b8;font-weight:400">(optional)</span></label>
          <input type="text" id="notes" placeholder="Any additional context…" />
        </div>
      </div>
      <button type="submit" class="btn-submit" id="submitBtn">&#x2795; Log Denial</button>
      <div class="form-error" id="formError"></div>
      <div class="form-success" id="formSuccess">Denial logged successfully!</div>
    </form>
  </div>

  <!-- Denial log table -->
  <div class="section-card">
    <h2>Denial Log</h2>
    <div class="table-wrap">
      <table class="denials-table" id="denialsTable">
        <thead><tr>
          <th>Date of Service</th>
          <th>Payer</th>
          <th>CPT</th>
          <th>Reason Code</th>
          <th>Amount</th>
          <th>Action</th>
        </tr></thead>
        <tbody id="denialsBody">${tableRows}</tbody>
      </table>
    </div>
  </div>
</div>
${FOOTER}

<script>
// ─── Denial code dropdown ───────────────────────────────────────────────────
const searchInput = document.getElementById('denialSearch');
const dropdown = document.getElementById('denialDropdown');
const codeInput = document.getElementById('denialCode');

searchInput.addEventListener('focus', () => { filterItems(''); dropdown.classList.add('open'); });
searchInput.addEventListener('input', () => { filterItems(searchInput.value); dropdown.classList.add('open'); codeInput.value = ''; });
document.addEventListener('click', (e) => { if (!e.target.closest('.denial-select-wrap')) dropdown.classList.remove('open'); });

function filterItems(q) {
  const lq = q.toLowerCase().replace(/\\s/g,'');
  dropdown.querySelectorAll('.denial-item').forEach(item => {
    item.style.display = item.textContent.toLowerCase().replace(/\\s/g,'').includes(lq) ? '' : 'none';
  });
}

dropdown.querySelectorAll('.denial-item').forEach(item => {
  item.addEventListener('mousedown', e => e.preventDefault());
  item.addEventListener('click', () => {
    searchInput.value = item.dataset.code + ' — ' + item.dataset.label;
    codeInput.value = item.dataset.code;
    dropdown.classList.remove('open');
  });
});

// ─── Form submit ────────────────────────────────────────────────────────────
document.getElementById('denialForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errEl = document.getElementById('formError');
  const sucEl = document.getElementById('formSuccess');
  const btn = document.getElementById('submitBtn');
  errEl.style.display = 'none';
  sucEl.style.display = 'none';

  const payer = document.getElementById('payer').value.trim();
  const cpt = document.getElementById('cptCode').value.trim();
  const code = document.getElementById('denialCode').value.trim();
  const date = document.getElementById('dateOfService').value;
  const amount = document.getElementById('claimAmount').value.trim();
  const notes = document.getElementById('notes').value.trim();

  if (!payer || !cpt || !code || !date || !amount) {
    errEl.textContent = 'Please fill in all required fields including the denial reason code.';
    errEl.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Logging…';

  try {
    const res = await fetch('/api/denials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payer, cpt_code: cpt, denial_reason_code: code, date_of_service: date, claim_amount: parseFloat(amount), notes })
    });
    const data = await res.json();
    if (!res.ok) { errEl.textContent = data.error || 'Error saving denial.'; errEl.style.display = 'block'; return; }
    sucEl.style.display = 'block';
    e.target.reset();
    searchInput.value = '';
    codeInput.value = '';
    // Reload page to refresh dashboard stats + table
    setTimeout(() => window.location.reload(), 800);
  } catch(err) {
    errEl.textContent = 'Network error — please try again.';
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = '✚ Log Denial';
  }
});

// ─── Share report ────────────────────────────────────────────────────────────
function shareReport() {
  const text = ${JSON.stringify(shareText)};
  const showCopied = () => {
    const msg = document.getElementById('copiedMsg');
    if (msg) { msg.style.display = 'inline'; setTimeout(() => { msg.style.display = 'none'; }, 2500); }
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(showCopied).catch(() => fallbackCopy(text, showCopied));
  } else {
    fallbackCopy(text, showCopied);
  }
}
function fallbackCopy(text, cb) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select(); document.execCommand('copy');
  document.body.removeChild(ta); cb();
}
</script>
</body>
</html>`);
});

app.get("/appeal-generator", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.redirect("/login?next=/appeal-generator");

  const url = new URL(c.req.url);
  const preCode = url.searchParams.get("denial_code") || url.searchParams.get("code") || "";
  const preCpt = url.searchParams.get("cpt") || "";
  const prePayer = url.searchParams.get("payer") || "";
  const preDate = url.searchParams.get("date") || "";
  const preAmount = url.searchParams.get("amount") || "";

  const codeOptions = DENIAL_CODES.map(d =>
    `<div class="denial-item" data-code="${escHtml(d.code)}" data-label="${escHtml(d.label)}">`
    + `<span class="code">${escHtml(d.code)}</span> — ${escHtml(d.label)}</div>`
  ).join("");

  const preCodeLabel = DENIAL_CODES.find(d => d.code === preCode)?.label || "";

  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Appeal Letter Generator — ClinicOS AI</title>
<style>
${SHARED_STYLES}
${APPEAL_STYLES}
body{background:#f1f5f9}
</style>
</head>
<body>
${buildNav(user)}
<div class="appeal-wrap">
  <div class="appeal-hero">
    <h1>&#x270D;&#xFE0F; Appeal Letter Generator</h1>
    <p>AI-powered appeal letters tailored to your denial code — ready in seconds.</p>
  </div>
  <div class="appeal-layout">
    <!-- Left: Form -->
    <div class="card">
      <h2 style="font-size:1.15rem;font-weight:700;color:#0f172a;margin-bottom:1.25rem">Claim Details</h2>
      <form id="appealForm" onsubmit="return false">

        <!-- Denial code searchable dropdown -->
        <div class="form-group">
          <label>Denial Reason Code *</label>
          <div class="denial-select-wrap">
            <input type="text" id="denialSearch" class="denial-search"
              placeholder="Search or select a denial code…"
              value="${escHtml(preCode ? preCode + ' — ' + preCodeLabel : '')}"
              autocomplete="off" />
            <input type="hidden" id="denialCode" name="denial_code" value="${escHtml(preCode)}" />
            <input type="hidden" id="denialLabel" name="denial_label" value="${escHtml(preCodeLabel)}" />
            <div class="denial-dropdown" id="denialDropdown">${codeOptions}</div>
          </div>
        </div>

        <div class="form-group">
          <label>Patient ID (de-identified) *</label>
          <input type="text" id="patientId" placeholder="e.g. PT-00123" required />
        </div>
        <div class="form-group">
          <label>Date of Service *</label>
          <input type="date" id="dateOfService" value="${escHtml(preDate)}" required />
        </div>
        <div class="form-group">
          <label>CPT Code *</label>
          <input type="text" id="cptCode" placeholder="e.g. 99213" value="${escHtml(preCpt)}" required />
        </div>
        <div class="form-group">
          <label>Payer Name *</label>
          <input type="text" id="payerName" placeholder="e.g. Blue Cross Blue Shield" value="${escHtml(prePayer)}" required />
        </div>
        <div class="form-group">
          <label>Billed Amount *</label>
          <div class="input-prefix">
            <span>$</span>
            <input type="number" id="billedAmount" placeholder="0.00" step="0.01" min="0" value="${escHtml(preAmount)}" required />
          </div>
        </div>
        <div class="form-group">
          <label>NPI (National Provider Identifier) *</label>
          <input type="text" id="npi" placeholder="e.g. 1234567890" required />
        </div>
        <div class="form-group">
          <label>Additional Notes <span style="color:#94a3b8;font-weight:400">(optional)</span></label>
          <textarea id="notes" rows="3" placeholder="Any additional context for the appeal (optional)" style="resize:vertical"></textarea>
        </div>

        <button type="button" class="btn-generate" id="generateBtn" onclick="generateAppeal()">
          <span id="btnLabel">&#x26A1; Generate Appeal Letter</span>
          <span id="btnSpinner" class="spinner" style="display:none"></span>
        </button>
        <div id="formError" class="error-msg" style="display:none"></div>
      </form>
    </div>

    <!-- Right: Letter output -->
    <div class="card" id="outputCard">
      <div id="letterPlaceholder" class="letter-placeholder">
        <div class="icon">&#x1F4DC;</div>
        <p>Fill in the form and click <strong>Generate Appeal Letter</strong><br>to draft a professional appeal in seconds.</p>
      </div>
      <div id="letterOutput" style="display:none">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.75rem;flex-wrap:wrap;gap:.5rem">
          <h2 style="font-size:1.1rem;font-weight:700;color:#0f172a">Generated Appeal Letter</h2>
          <span id="codeTag" style="background:#f0f9ff;border:1px solid #bae6fd;color:#0284c7;border-radius:20px;padding:.25rem .75rem;font-size:.78rem;font-weight:700"></span>
        </div>
        <div id="letterFull">
          <pre id="letterText" class="letter-box"></pre>
          <div class="letter-actions">
            <button class="btn-action btn-copy" onclick="copyLetter()">
              <span id="copyIcon">&#x1F4CB;</span> <span id="copyLabel">Copy Letter</span>
            </button>
            <button class="btn-action btn-download" onclick="downloadLetter()">
              &#x2B07; Download .txt
            </button>
            <button class="btn-action btn-mark-sent" id="markSentBtn" onclick="markAsSent()" style="background:#e0f2fe;color:#0284c7;border:1.5px solid #bae6fd">
              <span id="markSentLabel">&#x1F4EC; Mark as Sent</span>
            </button>
          </div>
          <div id="trackerToast" style="display:none;margin-top:.75rem;background:#d1fae5;border:1px solid #6ee7b7;color:#065f46;border-radius:8px;padding:.65rem 1rem;font-size:.9rem;font-weight:600">&#x2705; Appeal logged to tracker.</div>
        </div>
        <div id="previewWrap" style="display:none">
          <div class="preview-overlay">
            <pre id="previewText" class="letter-box preview-blur"></pre>
            <div class="upgrade-card">
              <div class="upgrade-inner">
                <div style="font-size:2rem;margin-bottom:.5rem">&#x1F512;</div>
                <h3>Upgrade to unlock full letters</h3>
                <p>Upgrade to Growth or Professional to generate, copy, and download complete appeal letters.</p>
                <a href="/checkout/growth" class="btn btn-primary" style="padding:.7rem 1.5rem;font-size:.9rem;display:inline-block">Start Free Trial &#x2197;</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
${FOOTER}

<script>
// ─── Denial code searchable dropdown ──────────────────────────────
const searchInput = document.getElementById('denialSearch');
const dropdown = document.getElementById('denialDropdown');
const codeInput = document.getElementById('denialCode');
const labelInput = document.getElementById('denialLabel');

searchInput.addEventListener('focus', () => {
  filterItems('');
  dropdown.classList.add('open');
});
searchInput.addEventListener('input', () => {
  filterItems(searchInput.value);
  dropdown.classList.add('open');
  codeInput.value = '';
  labelInput.value = '';
});
document.addEventListener('click', (e) => {
  if (!e.target.closest('.denial-select-wrap')) dropdown.classList.remove('open');
});

function filterItems(q) {
  const lq = q.toLowerCase().replace(/\\s/g,'');
  dropdown.querySelectorAll('.denial-item').forEach(item => {
    const text = item.textContent.toLowerCase().replace(/\\s/g,'');
    item.style.display = text.includes(lq) ? '' : 'none';
  });
}

dropdown.querySelectorAll('.denial-item').forEach(item => {
  item.addEventListener('click', () => {
    const code = item.dataset.code;
    const label = item.dataset.label;
    searchInput.value = code + ' — ' + label;
    codeInput.value = code;
    labelInput.value = label;
    dropdown.classList.remove('open');
    dropdown.querySelectorAll('.denial-item').forEach(i => i.classList.remove('active'));
    item.classList.add('active');
  });
  item.addEventListener('mousedown', e => e.preventDefault());
});

// ─── Generate appeal ─────────────────────────────────────────────
let lastDenialCode = '';
let lastLetter = '';
let isPreview = false;
let lastFormData = {};

async function generateAppeal() {
  const code = document.getElementById('denialCode').value.trim();
  const denialLabel = document.getElementById('denialLabel').value.trim();
  const patientId = document.getElementById('patientId').value.trim();
  const dateOfService = document.getElementById('dateOfService').value;
  const cptCode = document.getElementById('cptCode').value.trim();
  const payerName = document.getElementById('payerName').value.trim();
  const billedAmount = document.getElementById('billedAmount').value.trim();
  const npi = document.getElementById('npi').value.trim();
  const notes = document.getElementById('notes').value.trim();
  const errEl = document.getElementById('formError');
  errEl.style.display = 'none';

  if (!code) { showErr('Please select a denial reason code.'); return; }
  if (!patientId) { showErr('Patient ID is required.'); return; }
  if (!dateOfService) { showErr('Date of service is required.'); return; }
  if (!cptCode) { showErr('CPT code is required.'); return; }
  if (!payerName) { showErr('Payer name is required.'); return; }
  if (!billedAmount) { showErr('Billed amount is required.'); return; }
  if (!npi) { showErr('NPI is required.'); return; }

  setLoading(true);
  try {
    const res = await fetch('/api/appeal/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ denial_code: code, denial_label: denialLabel, patient_id: patientId,
        date_of_service: dateOfService, cpt_code: cptCode, payer_name: payerName,
        billed_amount: parseFloat(billedAmount), npi, notes })
    });
    const data = await res.json();
    if (!res.ok) {
      showErr(data.error || 'Unable to generate letter at this time — please try again shortly.');
      return;
    }
    lastDenialCode = code;
    lastLetter = data.letter;
    isPreview = !!data.preview_only;
    lastFormData = { denial_code: code, cpt_code: cptCode, payer: payerName, billed_amount: parseFloat(billedAmount)||0 };
    renderLetter(data.letter, code, denialLabel, isPreview);
  } catch(e) {
    showErr('Unable to generate letter at this time — please try again shortly.');
  } finally {
    setLoading(false);
  }
}

function renderLetter(text, code, label, previewOnly) {
  document.getElementById('letterPlaceholder').style.display = 'none';
  document.getElementById('letterOutput').style.display = 'block';
  document.getElementById('codeTag').textContent = code + ' — ' + label;
  if (previewOnly) {
    document.getElementById('letterFull').style.display = 'none';
    document.getElementById('previewWrap').style.display = 'block';
    document.getElementById('previewText').textContent = text;
  } else {
    document.getElementById('letterFull').style.display = 'block';
    document.getElementById('previewWrap').style.display = 'none';
    document.getElementById('letterText').textContent = text;
  }
}

function showErr(msg) {
  const el = document.getElementById('formError');
  el.textContent = msg;
  el.style.display = 'block';
}

function setLoading(on) {
  const btn = document.getElementById('generateBtn');
  const lbl = document.getElementById('btnLabel');
  const spin = document.getElementById('btnSpinner');
  btn.disabled = on;
  lbl.textContent = on ? 'Drafting your appeal letter...' : '⚡ Generate Appeal Letter';
  spin.style.display = on ? '' : 'none';
}

async function copyLetter() {
  try {
    await navigator.clipboard.writeText(lastLetter);
    document.getElementById('copyLabel').textContent = 'Copied!';
    setTimeout(() => document.getElementById('copyLabel').textContent = 'Copy Letter', 2000);
  } catch(e) {}
}

function downloadLetter() {
  const date = new Date().toISOString().slice(0,10);
  const filename = 'appeal-' + lastDenialCode.replace(/[^a-z0-9]/gi,'-') + '-' + date + '.txt';
  const blob = new Blob([lastLetter], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

async function markAsSent() {
  if (!lastLetter || isPreview) return;
  const btn = document.getElementById('markSentBtn');
  const lbl = document.getElementById('markSentLabel');
  btn.disabled = true;
  lbl.textContent = 'Saving…';
  try {
    const res = await fetch('/api/appeals/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...lastFormData, letter_text: lastLetter })
    });
    if (res.ok) {
      document.getElementById('trackerToast').style.display = 'block';
      lbl.textContent = '✅ Logged';
    } else {
      lbl.textContent = '📪 Mark as Sent';
      btn.disabled = false;
    }
  } catch(e) {
    lbl.textContent = '📪 Mark as Sent';
    btn.disabled = false;
  }
}
</script>
<script>navigator.sendBeacon("/api/_ping");</script>
</body>
</html>`);
});

// ─── API: Generate appeal letter ──────────────────────────────────────────────
app.post("/api/appeal/generate", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  if (isReadOnly(user)) return c.json({ error: "View only — contact your Admin to request access" }, 403);

  // Check plan
  const userRow = await c.env.DB.prepare("SELECT plan FROM users WHERE id = ?")
    .bind(user.user_id).first<{ plan: string | null }>();
  const plan = (userRow?.plan || "").toLowerCase();
  const isFullAccess = plan === "growth" || plan === "professional" || plan === "pro";
  const isStarter = plan === "starter";
  // No plan at all: still allow (be generous; gate only if desired)
  // Per spec: starter = first paragraph preview, growth/pro = full

  let body: {
    denial_code?: string; denial_label?: string; patient_id?: string;
    date_of_service?: string; cpt_code?: string; payer_name?: string;
    billed_amount?: number; npi?: string; notes?: string;
  };
  try { body = await c.req.json(); } catch { return c.json({ error: "Invalid request body" }, 400); }

  const { denial_code, denial_label, patient_id, date_of_service, cpt_code, payer_name, billed_amount, npi, notes } = body;
  if (!denial_code || !patient_id || !date_of_service || !cpt_code || !payer_name || !billed_amount || !npi) {
    return c.json({ error: "Missing required fields" }, 400);
  }

  const codeObj = DENIAL_CODES.find(d => d.code === denial_code);
  const codeLabel = denial_label || codeObj?.label || denial_code;

  const prompt = `You are a certified professional coder (CPC) and medical billing specialist with 20+ years of experience writing formal insurance appeal letters. Write a complete, professional medical billing appeal letter for the following denied claim.

CLAIM DETAILS:
- Provider NPI: ${npi}
- Patient ID: ${patient_id}
- Date of Service: ${date_of_service}
- CPT Code: ${cpt_code}
- Payer: ${payer_name}
- Billed Amount: $${billed_amount}
- Denial Reason Code: ${denial_code} — ${codeLabel}
${notes ? `- Additional Context: ${notes}` : ""}

LETTER REQUIREMENTS:
1. Opening paragraph: State provider NPI, patient ID, date of service, CPT code, billed amount, and the denial code with its plain-English meaning. Reference the specific claim being appealed.
2. Specific rebuttal paragraph: Directly address the denial reason code "${denial_code}" (${codeLabel}). Provide a fact-based, code-specific argument for why the denial should be overturned.
3. Clinical and coding rationale: Cite relevant AMA CPT guidelines, CMS Local Coverage Determinations (LCDs) or National Coverage Determinations (NCDs), NCCI edits, or other authoritative billing policies that support this appeal. Be specific to CPT code ${cpt_code} and denial code ${denial_code}.
4. Request for reconsideration within the payer's timely filing window (typically 90-180 days from the denial date). Ask for written response.
5. Professional closing.

Format as a formal business letter. Use today's date. Address it to: Appeals Department, ${payer_name}. Sign it from: Provider of Record (NPI: ${npi}).

Write the complete letter now:`;

  let letterText = "";
  try {
    const openai = new OpenAI({
      baseURL: `${c.env.LAUNCHYARD_API_BASE_URL}/v1/ai/openai/v1`,
      apiKey: c.env.LAUNCHYARD_API_KEY,
    });
    const resp = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      max_tokens: 1200,
    });
    letterText = resp.choices?.[0]?.message?.content?.trim() || "";
    if (!letterText) throw new Error("Empty response from AI");
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("402") || msg.includes("ai_budget_exhausted")) {
      return c.json({ error: "Unable to generate letter at this time — AI budget exhausted. Please contact your administrator." }, 503);
    }
    return c.json({ error: "Unable to generate letter at this time — please try again shortly." }, 503);
  }

  // Save to DB
  const letterId = generateId();
  await c.env.DB.prepare(
    `INSERT INTO appeal_letters (id,user_id,denial_code,denial_label,patient_id,date_of_service,cpt_code,payer_name,billed_amount,npi,notes,letter_text)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(letterId, user.user_id, denial_code, codeLabel, patient_id, date_of_service, cpt_code, payer_name, billed_amount, npi, notes || null, letterText).run().catch(() => {});

  // For starter plan: return only first paragraph
  if (isStarter && !isFullAccess) {
    const firstParagraph = letterText.split(/\n\n+/)[0] || letterText.slice(0, 400);
    return c.json({ letter: firstParagraph, preview_only: true });
  }

  return c.json({ letter: letterText, preview_only: false });
});

// ─── Appeal Letters list (for My Claims tab) ──────────────────────────────────
app.get("/api/appeal/letters", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  const afL = accountFilter(user);
  const letters = await c.env.DB.prepare(
    `SELECT id,denial_code,denial_label,patient_id,date_of_service,cpt_code,payer_name,billed_amount,letter_text,created_at FROM appeal_letters WHERE ${afL.clause} ORDER BY created_at DESC LIMIT 100`
  ).bind(afL.param).all();
  return c.json({ letters: letters.results || [] });
});

// ─── Appeals Tracker API ──────────────────────────────────────────────────────

app.post("/api/appeals/track", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  if (isReadOnly(user)) return c.json({ error: "Read-only" }, 403);

  let body: { denial_code?: string; cpt_code?: string; payer?: string; billed_amount?: number; letter_text?: string };
  try { body = await c.req.json(); } catch { return c.json({ error: "Invalid JSON" }, 400); }

  const { denial_code, cpt_code, payer, billed_amount, letter_text } = body;
  if (!denial_code || !cpt_code || !payer) return c.json({ error: "Missing required fields" }, 400);

  const today = new Date().toISOString().slice(0, 10);
  const id = generateId();
  await c.env.DB.prepare(
    `INSERT INTO appeals_tracker (id,user_id,denial_code,cpt_code,payer,billed_amount,date_sent,status,letter_text)
     VALUES (?,?,?,?,?,?,?,'Sent',?)`
  ).bind(id, user.user_id, denial_code, cpt_code, payer, billed_amount || 0, today, letter_text || null).run();

  return c.json({ id });
});

app.patch("/api/appeals/:id/status", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  if (isReadOnly(user)) return c.json({ error: "Read-only" }, 403);

  const appealId = c.req.param("id");
  let body: { status?: string };
  try { body = await c.req.json(); } catch { return c.json({ error: "Invalid JSON" }, 400); }

  const validStatuses = ["Sent", "Approved", "Denied", "Pending Info", "Withdrawn"];
  const { status } = body;
  if (!status || !validStatuses.includes(status)) return c.json({ error: "Invalid status" }, 400);

  // Verify ownership
  const row = await c.env.DB.prepare("SELECT user_id FROM appeals_tracker WHERE id = ?").bind(appealId).first<{ user_id: string }>();
  if (!row) return c.json({ error: "Not found" }, 404);
  if (row.user_id !== user.user_id) return c.json({ error: "Forbidden" }, 403);

  const resolvedStatuses = ["Approved", "Denied", "Withdrawn"];
  const resolvedAt = resolvedStatuses.includes(status) ? new Date().toISOString().slice(0, 10) : null;

  await c.env.DB.prepare(
    `UPDATE appeals_tracker SET status=?, resolved_at=?, updated_at=unixepoch() WHERE id=?`
  ).bind(status, resolvedAt, appealId).run();

  return c.json({ ok: true });
});

// ─── Appeals Tracker Page ─────────────────────────────────────────────────────

app.get("/appeals", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.redirect("/login?next=/appeals");

  const isPro = isProfessionalPlan(user);

  // Load data for Pro users
  let appeals: Array<{
    id: string; denial_code: string; cpt_code: string; payer: string;
    billed_amount: number; date_sent: string; status: string; resolved_at: string | null;
  }> = [];
  let totalOpen = 0, totalApprovedMonth = 0;
  let estimatedRecovered = 0, avgDaysResolution: number | null = null;

  if (isPro) {
    const rows = await c.env.DB.prepare(
      `SELECT id,denial_code,cpt_code,payer,billed_amount,date_sent,status,resolved_at FROM appeals_tracker WHERE user_id=? ORDER BY date_sent DESC LIMIT 500`
    ).bind(user.user_id).all<{ id: string; denial_code: string; cpt_code: string; payer: string; billed_amount: number; date_sent: string; status: string; resolved_at: string | null }>();
    appeals = rows.results || [];

    const nowMonth = new Date().toISOString().slice(0, 7); // YYYY-MM
    totalOpen = appeals.filter(a => a.status === "Sent" || a.status === "Pending Info").length;
    const approvedThisMonth = appeals.filter(a => a.status === "Approved" && a.resolved_at && a.resolved_at.startsWith(nowMonth));
    totalApprovedMonth = approvedThisMonth.length;
    estimatedRecovered = approvedThisMonth.reduce((sum, a) => sum + (a.billed_amount || 0), 0);

    const resolved = appeals.filter(a => ["Approved","Denied","Withdrawn"].includes(a.status) && a.resolved_at && a.date_sent);
    if (resolved.length > 0) {
      const totalDays = resolved.reduce((sum, a) => {
        const d1 = new Date(a.date_sent).getTime();
        const d2 = new Date(a.resolved_at!).getTime();
        return sum + Math.max(0, Math.round((d2 - d1) / 86400000));
      }, 0);
      avgDaysResolution = Math.round(totalDays / resolved.length);
    }
  }

  const today = new Date().toISOString().slice(0, 10);

  function daysOutstanding(dateSent: string): number {
    return Math.max(0, Math.round((new Date(today).getTime() - new Date(dateSent).getTime()) / 86400000));
  }

  function statusBadge(status: string): string {
    const map: Record<string, string> = {
      "Sent": "background:#dbeafe;color:#1d4ed8",
      "Approved": "background:#d1fae5;color:#065f46",
      "Denied": "background:#fee2e2;color:#b91c1c",
      "Pending Info": "background:#fef3c7;color:#92400e",
      "Withdrawn": "background:#f1f5f9;color:#64748b",
    };
    const style = map[status] || "background:#f1f5f9;color:#64748b";
    return `<span style="display:inline-block;${style};border-radius:20px;padding:.18rem .65rem;font-size:.78rem;font-weight:700">${escHtml(status)}</span>`;
  }

  const tableRows = isPro ? appeals.map(a => {
    const days = daysOutstanding(a.date_sent);
    const daysBg = days >= 60 ? "background:#fee2e2" : days >= 30 ? "background:#fef3c7" : "";
    const followUpBtn = a.status === "Denied"
      ? `<a href="/appeal-generator?denial_code=${encodeURIComponent(a.denial_code)}&cpt=${encodeURIComponent(a.cpt_code)}&payer=${encodeURIComponent(a.payer)}&amount=${encodeURIComponent(a.billed_amount)}" class="btn-tbl-action" style="background:#fef3c7;color:#92400e;border:1px solid #fde68a">&#x1F504; Follow-up</a>` : '';
    return `<tr>
      <td><code style="font-size:.85rem">${escHtml(a.denial_code)}</code></td>
      <td>${escHtml(a.cpt_code)}</td>
      <td>${escHtml(a.payer)}</td>
      <td style="white-space:nowrap">${escHtml(a.date_sent)}</td>
      <td>$${(a.billed_amount || 0).toFixed(2)}</td>
      <td>${statusBadge(a.status)}</td>
      <td style="${daysBg};text-align:center;border-radius:6px;font-weight:${days>=30?'700':'400'}">${days}d</td>
      <td style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap">
        <select class="status-select" onchange="updateStatus('${escHtml(a.id)}', this)" data-current="${escHtml(a.status)}" style="border:1px solid #e2e8f0;border-radius:6px;padding:.3rem .5rem;font-size:.82rem;background:#fff;cursor:pointer">
          ${["Sent","Approved","Denied","Pending Info","Withdrawn"].map(s => `<option${s===a.status?' selected':''}>${escHtml(s)}</option>`).join('')}
        </select>
        ${followUpBtn}
      </td>
    </tr>`;
  }).join('') : '';

  // Gated preview rows
  const sampleRows = !isPro ? `
    <tr style="filter:blur(4px);user-select:none"><td><code>CO-50</code></td><td>99213</td><td>Blue Cross</td><td>2025-03-10</td><td>$185.00</td><td><span style="background:#dbeafe;color:#1d4ed8;border-radius:20px;padding:.18rem .65rem;font-size:.78rem;font-weight:700">Sent</span></td><td>45d</td><td>—</td></tr>
    <tr style="filter:blur(4px);user-select:none"><td><code>CO-197</code></td><td>27447</td><td>Aetna</td><td>2025-02-20</td><td>$4,200.00</td><td><span style="background:#fee2e2;color:#b91c1c;border-radius:20px;padding:.18rem .65rem;font-size:.78rem;font-weight:700">Denied</span></td><td>63d</td><td>—</td></tr>
    <tr style="filter:blur(4px);user-select:none"><td><code>CO-11</code></td><td>93000</td><td>United HC</td><td>2025-04-01</td><td>$320.00</td><td><span style="background:#d1fae5;color:#065f46;border-radius:20px;padding:.18rem .65rem;font-size:.78rem;font-weight:700">Approved</span></td><td>12d</td><td>—</td></tr>
  ` : '';

  const upgradeOverlay = !isPro ? `
    <div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;z-index:10;background:rgba(255,255,255,.7);border-radius:12px">
      <div style="background:#fff;border:1.5px solid #e2e8f0;border-radius:16px;padding:2rem 2.5rem;text-align:center;max-width:420px;box-shadow:0 8px 32px rgba(0,0,0,.12)">
        <div style="font-size:2.5rem;margin-bottom:.5rem">&#x1F512;</div>
        <h3 style="font-size:1.2rem;font-weight:800;color:#0f172a;margin-bottom:.5rem">Professional Plan Required</h3>
        <p style="color:#64748b;margin-bottom:1.25rem;font-size:.95rem">The Appeals Tracker is a Professional-only feature. Upgrade to track, follow up, and recover denied claims.</p>
        <a href="/pricing" class="btn btn-primary" style="display:inline-block;padding:.75rem 1.75rem;font-size:.95rem">Upgrade to Professional &#x2197;</a>
      </div>
    </div>` : '';

  const cardVal = (v: string | number, blur = false) =>
    blur ? `<span style="filter:blur(6px);user-select:none">${v}</span>` : `${v}`;

  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Appeals Tracker — ClinicOS AI</title>
<style>
${SHARED_STYLES}
body{background:#f1f5f9}
.at-wrap{max-width:1200px;margin:0 auto;padding:2rem 1.5rem}
.at-hero{margin-bottom:1.75rem}
.at-hero h1{font-size:1.8rem;font-weight:800;color:#0f172a;margin:0 0 .3rem}
.at-hero p{color:#64748b;font-size:1rem}
.at-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:1rem;margin-bottom:1.75rem}
.at-card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:1.25rem 1.5rem}
.at-card .label{font-size:.82rem;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:.04em;margin-bottom:.5rem}
.at-card .value{font-size:2rem;font-weight:800;color:#0f172a}
.at-card .sub{font-size:.8rem;color:#94a3b8;margin-top:.25rem}
.at-table-wrap{background:#fff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;position:relative}
.at-table-wrap table{width:100%;border-collapse:collapse;font-size:.88rem}
.at-table-wrap th{background:#f8fafc;padding:.75rem 1rem;text-align:left;font-weight:700;color:#334155;border-bottom:1px solid #e2e8f0;white-space:nowrap}
.at-table-wrap td{padding:.7rem 1rem;border-bottom:1px solid #f1f5f9;color:#0f172a;vertical-align:middle}
.at-table-wrap tr:last-child td{border-bottom:none}
.btn-tbl-action{display:inline-block;padding:.3rem .75rem;border-radius:6px;font-size:.8rem;font-weight:600;text-decoration:none;cursor:pointer;border:1px solid transparent}
.status-select:focus{outline:2px solid var(--electric-blue)}
</style>
</head>
<body>
${buildNav(user)}
<div class="at-wrap">
  <div class="at-hero">
    <h1>&#x1F4EB; Appeals Tracker</h1>
    <p>Track the status and recovery rate of all your submitted insurance appeals.</p>
  </div>

  <!-- Summary Cards -->
  <div class="at-cards">
    <div class="at-card">
      <div class="label">Total Open Appeals</div>
      <div class="value">${cardVal(isPro ? totalOpen : 0, !isPro)}</div>
      <div class="sub">Status: Sent or Pending Info</div>
    </div>
    <div class="at-card">
      <div class="label">Approved This Month</div>
      <div class="value">${cardVal(isPro ? totalApprovedMonth : 0, !isPro)}</div>
      <div class="sub">${new Date().toLocaleString('default',{month:'long',year:'numeric'})}</div>
    </div>
    <div class="at-card">
      <div class="label">Est. Recovered Revenue</div>
      <div class="value">${cardVal(isPro ? '$' + estimatedRecovered.toFixed(0) : '$0', !isPro)}</div>
      <div class="sub">Approved billed amounts this month</div>
    </div>
    <div class="at-card">
      <div class="label">Avg Days to Resolution</div>
      <div class="value">${cardVal(isPro ? (avgDaysResolution !== null ? avgDaysResolution + 'd' : '—') : '—', !isPro)}</div>
      <div class="sub">Approved/Denied/Withdrawn</div>
    </div>
  </div>

  <!-- Table -->
  <div class="at-table-wrap">
    ${upgradeOverlay}
    <table>
      <thead>
        <tr>
          <th>Denial Code</th>
          <th>CPT Code</th>
          <th>Payer</th>
          <th>Date Sent</th>
          <th>Billed Amount</th>
          <th>Status</th>
          <th>Days Out</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="appealsBody">
        ${isPro ? (tableRows || '<tr><td colspan="8" style="text-align:center;padding:2rem;color:#94a3b8">No appeals tracked yet. Use the <a href="/appeal-generator" style="color:#0284c7">Appeal Generator</a> and click \'Mark as Sent\' to log your first appeal.</td></tr>') : sampleRows}
      </tbody>
    </table>
  </div>
</div>
${FOOTER}
<script>
async function updateStatus(id, selectEl) {
  const newStatus = selectEl.value;
  const prev = selectEl.dataset.current;
  selectEl.disabled = true;
  try {
    const res = await fetch('/api/appeals/' + id + '/status', {
      method: 'PATCH',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ status: newStatus })
    });
    if (res.ok) {
      selectEl.dataset.current = newStatus;
      // Update the status badge in this row
      const row = selectEl.closest('tr');
      const badges = {'Sent':'background:#dbeafe;color:#1d4ed8','Approved':'background:#d1fae5;color:#065f46','Denied':'background:#fee2e2;color:#b91c1c','Pending Info':'background:#fef3c7;color:#92400e','Withdrawn':'background:#f1f5f9;color:#64748b'};
      const badgeStyle = badges[newStatus] || 'background:#f1f5f9;color:#64748b';
      row.cells[5].innerHTML = '<span style="display:inline-block;'+badgeStyle+';border-radius:20px;padding:.18rem .65rem;font-size:.78rem;font-weight:700">'+newStatus+'</span>';
      // Show/hide follow-up btn
      const actionsCell = row.cells[7];
      const existingFU = actionsCell.querySelector('.fu-btn');
      if (existingFU) existingFU.remove();
      if (newStatus === 'Denied') {
        // add follow-up button if denied
        const fuLink = document.createElement('a');
        fuLink.className = 'btn-tbl-action fu-btn';
        fuLink.style.cssText = 'background:#fef3c7;color:#92400e;border:1px solid #fde68a';
        fuLink.textContent = '🔄 Follow-up';
        // reconstruct href from existing data — not perfect but usable
        fuLink.href = '/appeal-generator';
        actionsCell.appendChild(fuLink);
      }
    } else {
      selectEl.value = prev;
    }
  } catch(e) {
    selectEl.value = prev;
  }
  selectEl.disabled = false;
}
</script>
<script>navigator.sendBeacon("/api/_ping");</script>
</body>
</html>`);
});

// ─── Eligibility Verification ────────────────────────────────────────────────

const PAYERS = [
  "Medicare", "Medicaid", "Blue Cross Blue Shield", "United Healthcare",
  "Aetna", "Cigna", "Humana", "Other"
];

// Demo eligibility data keyed by payer — used in demo mode
function demoEligibilityResult(payer: string, memberId: string, cptCode: string | null): Record<string, unknown> {
  const now = new Date().toISOString();
  const demoMap: Record<string, Partial<{
    status: string; plan_name: string; group_number: string;
    deductible_total: number; deductible_remaining: number;
    copay: number; coinsurance_pct: number;
    prior_auth_required: string; timely_filing_limit: string;
  }>> = {
    "Medicare":              { status: "active", plan_name: "Medicare Part B",          group_number: "DEMO-MCR",  deductible_total: 240,    deductible_remaining: 120,  copay: 0,   coinsurance_pct: 20, prior_auth_required: "Unknown",  timely_filing_limit: "1 year from DOS" },
    "Medicaid":              { status: "active", plan_name: "Medicaid Standard",         group_number: "DEMO-MCD",  deductible_total: 0,      deductible_remaining: 0,    copay: 3,   coinsurance_pct: 0,  prior_auth_required: "Yes",      timely_filing_limit: "90 days from DOS" },
    "Blue Cross Blue Shield":{ status: "active", plan_name: "BCBS PPO Plus",             group_number: "DEMO-BCBS", deductible_total: 1500,   deductible_remaining: 875,  copay: 30,  coinsurance_pct: 20, prior_auth_required: "No",       timely_filing_limit: "180 days from DOS" },
    "United Healthcare":     { status: "active", plan_name: "UHC Choice Plus",           group_number: "DEMO-UHC",  deductible_total: 2000,   deductible_remaining: 1250, copay: 40,  coinsurance_pct: 20, prior_auth_required: "No",       timely_filing_limit: "180 days from DOS" },
    "Aetna":                 { status: "active", plan_name: "Aetna Open Access HMO",     group_number: "DEMO-AETNA",deductible_total: 1000,   deductible_remaining: 400,  copay: 25,  coinsurance_pct: 15, prior_auth_required: "Yes",      timely_filing_limit: "180 days from DOS" },
    "Cigna":                 { status: "active", plan_name: "Cigna Connect 1500",        group_number: "DEMO-CIGNA",deductible_total: 1500,   deductible_remaining: 750,  copay: 35,  coinsurance_pct: 20, prior_auth_required: "No",       timely_filing_limit: "365 days from DOS" },
    "Humana":                { status: "active", plan_name: "Humana Gold Plus HMO",      group_number: "DEMO-HUM",  deductible_total: 500,    deductible_remaining: 200,  copay: 20,  coinsurance_pct: 10, prior_auth_required: "Unknown",  timely_filing_limit: "365 days from DOS" },
    "Other":                 { status: "unverified", plan_name: "Unknown Plan",          group_number: "—",         deductible_total: 0,      deductible_remaining: 0,    copay: 0,   coinsurance_pct: 0,  prior_auth_required: "Unknown",  timely_filing_limit: "Unknown" },
  };
  const d = demoMap[payer] || demoMap["Other"];
  return {
    demo: true,
    status: d.status,
    plan_name: d.plan_name,
    group_number: d.group_number,
    deductible_total_cents: (d.deductible_total || 0) * 100,
    deductible_remaining_cents: (d.deductible_remaining || 0) * 100,
    copay_cents: cptCode ? (d.copay || 0) * 100 : null,
    coinsurance_pct: cptCode ? (d.coinsurance_pct || 0) : null,
    prior_auth_required: d.prior_auth_required,
    timely_filing_limit: d.timely_filing_limit,
    checked_at: now,
    member_id_suffix: memberId.slice(-4),
    payer,
    cpt_code: cptCode || null,
  };
}

app.get("/eligibility", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.redirect("/login?next=/eligibility");

  const userRow = await c.env.DB.prepare("SELECT plan FROM users WHERE id = ?")
    .bind(user.user_id).first<{ plan: string | null }>();
  const plan = (userRow?.plan || "").toLowerCase();
  const isGrowthPlus = plan === "growth" || plan === "professional" || plan === "pro";
  // Growth+ gets full access; starter/trial/no-plan see locked overlay

  const payerOptions = PAYERS.map(p => `<option value="${p}">${p}</option>`).join("");

  const lockedOverlay = !isGrowthPlus ? `
  <div id="eligLockedOverlay" style="position:absolute;inset:0;background:rgba(255,255,255,.92);backdrop-filter:blur(4px);border-radius:16px;z-index:10;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:2rem">
    <div style="font-size:2.5rem;margin-bottom:.75rem">&#x1F512;</div>
    <h3 style="font-size:1.3rem;font-weight:800;color:#0f172a;margin:0 0 .5rem">Growth Plan Required</h3>
    <p style="color:#64748b;max-width:360px;margin:0 0 1.25rem;font-size:.95rem">Eligibility verification is available on Growth ($299/mo) and Professional ($599/mo) plans.</p>
    <a href="/#pricing" style="display:inline-block;padding:.65rem 1.4rem;background:linear-gradient(135deg,#0284c7,#06b6d4);color:#fff;border-radius:9px;font-weight:700;font-size:.95rem;text-decoration:none">Upgrade to Growth &#x2192;</a>
  </div>` : "";

  return c.html(`<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Eligibility Verification &#x2014; ClinicOS AI</title>
<style>
${SHARED_STYLES}
body{background:#f1f5f9}
.elig-wrap{max-width:820px;margin:0 auto;padding:2.5rem 1.5rem 5rem}
.card{background:#fff;border-radius:16px;border:1px solid #e2e8f0;padding:2rem;margin-bottom:1.5rem;box-shadow:0 4px 16px rgba(0,0,0,.05);position:relative}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem 1.5rem}
@media(max-width:600px){.form-grid{grid-template-columns:1fr}}
.form-group{display:flex;flex-direction:column;gap:.35rem}
.form-group label{font-weight:600;font-size:.88rem;color:#374151}
.form-group input,.form-group select{padding:.65rem .85rem;border:1.5px solid #e2e8f0;border-radius:9px;font-size:.95rem;color:#0f172a;font-family:inherit;background:#fff;transition:border-color .2s}
.form-group input:focus,.form-group select:focus{outline:none;border-color:#0284c7;box-shadow:0 0 0 3px rgba(2,132,199,.1)}
.form-group .helper{font-size:.78rem;color:#64748b;margin-top:.15rem}
.form-full{grid-column:1/-1}
.btn-primary{display:inline-flex;align-items:center;justify-content:center;gap:.5rem;padding:.8rem 2rem;background:linear-gradient(135deg,#0284c7,#06b6d4);color:#fff;border:none;border-radius:10px;font-size:1rem;font-weight:700;cursor:pointer;transition:opacity .2s;width:100%;margin-top:.75rem}
.btn-primary:hover:not(:disabled){opacity:.9}
.btn-primary:disabled{opacity:.6;cursor:not-allowed}
/* Result panel */
.result-panel{display:none}
.result-panel.visible{display:block}
.status-badge{display:inline-flex;align-items:center;gap:.5rem;padding:.55rem 1.1rem;border-radius:24px;font-size:1rem;font-weight:700}
.badge-active{background:#dcfce7;color:#166534;border:1.5px solid #86efac}
.badge-unverified{background:#fffbeb;color:#92400e;border:1.5px solid #fcd34d}
.badge-inactive{background:#fef2f2;color:#991b1b;border:1.5px solid #fca5a5}
.result-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:1rem;margin-top:1.25rem}
.result-item{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:.85rem 1rem}
.result-item .ri-label{font-size:.72rem;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:.3rem}
.result-item .ri-val{font-size:1rem;font-weight:700;color:#0f172a}
.demo-banner{background:#fef3c7;border:1.5px solid #f59e0b;border-radius:10px;padding:1rem 1.25rem;margin-bottom:1.5rem;display:flex;gap:.75rem;align-items:flex-start}
.info-banner{background:#fffbeb;border:1.5px solid #f59e0b;border-radius:10px;padding:1.1rem 1.25rem;margin-bottom:1.5rem;display:flex;gap:.75rem;align-items:flex-start}
.spinner{width:18px;height:18px;border:2.5px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head><body>
${buildNav(user)}
<div class="elig-wrap">
  <div style="margin-bottom:1.5rem">
    <h1 style="font-size:1.85rem;font-weight:800;color:#0f172a;margin:0 0 .35rem">&#x2705; Eligibility Verification</h1>
    <p style="color:#64748b;font-size:.97rem;margin:0">Verify patient insurance coverage in real time before submitting a claim.</p>
  </div>

  <!-- Persistent action required banner (dismissible) -->
  <div class="info-banner" id="eligActionBanner">
    <span style="font-size:1.3rem;flex-shrink:0">&#x26A0;&#xFE0F;</span>
    <div style="flex:1">
      <p style="font-weight:700;color:#92400e;margin:0 0 .3rem;font-size:.97rem">Live eligibility checks require API credentials</p>
      <p style="color:#78350f;margin:0 0 .6rem;font-size:.9rem">To run live eligibility checks, you need API credentials from <strong><a href="https://developer.availity.com" target="_blank" rel="noopener" style="color:#92400e">Availity</a></strong> or <strong>Change Healthcare (Optum)</strong>. Contact your account representative at either provider to obtain sandbox and production credentials. Once you have them, reply to any ClinicOS email and we'll wire them up same day.</p>
      <p style="color:#78350f;font-size:.88rem;margin:0">Until then, this tool runs in <strong>demo mode</strong> — all results are simulated and clearly labeled.</p>
    </div>
    <button onclick="document.getElementById('eligActionBanner').style.display='none'" style="background:none;border:none;color:#92400e;cursor:pointer;font-size:1.2rem;flex-shrink:0;line-height:1;padding:.1rem .2rem" title="Dismiss">&#x2715;</button>
  </div>

  <!-- Form card -->
  <div class="card" style="position:relative">
    ${lockedOverlay}
    <h2 style="font-size:1.1rem;font-weight:700;color:#0f172a;margin:0 0 1.25rem">Patient &amp; Coverage Details</h2>
    <form id="eligForm" onsubmit="submitElig(event)">
      <div class="form-grid">
        <div class="form-group">
          <label for="elig_fname">First Name *</label>
          <input type="text" id="elig_fname" name="first_name" required placeholder="Jane" autocomplete="off">
        </div>
        <div class="form-group">
          <label for="elig_lname">Last Name *</label>
          <input type="text" id="elig_lname" name="last_name" required placeholder="Smith" autocomplete="off">
        </div>
        <div class="form-group">
          <label for="elig_dob">Date of Birth *</label>
          <input type="date" id="elig_dob" name="dob" required>
        </div>
        <div class="form-group">
          <label for="elig_member_id">Member ID *</label>
          <input type="text" id="elig_member_id" name="member_id" required placeholder="e.g. XYZ123456789" autocomplete="off">
        </div>
        <div class="form-group form-full">
          <label for="elig_payer">Insurance Payer *</label>
          <select id="elig_payer" name="payer" required>
            <option value="">— Select payer —</option>
            ${payerOptions}
          </select>
        </div>
        <div class="form-group">
          <label for="elig_npi">Provider NPI *</label>
          <input type="text" id="elig_npi" name="npi" required placeholder="1234567890" pattern="[0-9]{10}" maxlength="10" inputmode="numeric">
          <span class="helper">10-digit National Provider Identifier</span>
        </div>
        <div class="form-group">
          <label for="elig_cpt">CPT Code <span style="font-weight:400;color:#9ca3af">(optional)</span></label>
          <input type="text" id="elig_cpt" name="cpt_code" placeholder="e.g. 99213" maxlength="10">
          <span class="helper">If provided, we'll return benefit details for this specific service code.</span>
        </div>
      </div>
      <button type="submit" class="btn-primary" id="eligSubmitBtn">
        <span id="eligBtnLabel">&#x1F50D; Check Eligibility</span>
        <span id="eligBtnSpinner" style="display:none" class="spinner"></span>
      </button>
    </form>
  </div>

  <!-- Results panel -->
  <div class="card result-panel" id="eligResult">
    <div id="demoBadge" style="display:none" class="demo-banner">
      <span style="font-size:1.1rem;flex-shrink:0">&#x1F9EA;</span>
      <div>
        <p style="font-weight:700;color:#92400e;margin:0 0 .2rem;font-size:.93rem">Demo Mode — Simulated Results</p>
        <p style="color:#78350f;font-size:.87rem;margin:0">These results are sample data. Connect Availity or Change Healthcare credentials to run live checks.</p>
      </div>
    </div>
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem;margin-bottom:1.25rem">
      <div>
        <div id="eligStatusBadge"></div>
      </div>
      <div style="font-size:.8rem;color:#94a3b8" id="eligTimestamp"></div>
    </div>
    <div class="result-grid" id="eligResultGrid"></div>
  </div>
</div>

${FOOTER}
<script>
async function submitElig(e) {
  e.preventDefault();
  const btn = document.getElementById('eligSubmitBtn');
  const lbl = document.getElementById('eligBtnLabel');
  const spin = document.getElementById('eligBtnSpinner');
  btn.disabled = true;
  lbl.textContent = 'Checking…';
  spin.style.display = 'inline-block';

  const fd = new FormData(e.target);
  const body = {
    first_name: fd.get('first_name'),
    last_name: fd.get('last_name'),
    dob: fd.get('dob'),
    member_id: fd.get('member_id'),
    payer: fd.get('payer'),
    npi: fd.get('npi'),
    cpt_code: fd.get('cpt_code') || null,
  };

  try {
    const r = await fetch('/api/eligibility/check', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Check failed');
    renderResult(data);
  } catch(err) {
    alert('Eligibility check failed: ' + err.message);
  } finally {
    btn.disabled = false;
    lbl.textContent = '\\uD83D\\uDD0D Check Eligibility';
    spin.style.display = 'none';
  }
}

function fmt$(cents) {
  if (cents === null || cents === undefined) return '—';
  return '$' + (cents / 100).toFixed(2).replace(/\\B(?=(\\d{3})+(?!\\d))/g, ',');
}

function renderResult(d) {
  const panel = document.getElementById('eligResult');
  panel.classList.add('visible');

  // Demo banner
  document.getElementById('demoBadge').style.display = d.demo ? 'flex' : 'none';

  // Status badge
  const statusMap = {
    active: ['Active Coverage', 'badge-active', '\\u2705'],
    unverified: ['Coverage Unverified', 'badge-unverified', '\\u26A0\\uFE0F'],
    inactive: ['Inactive / Not Found', 'badge-inactive', '\\u274C'],
  };
  const [label, cls, icon] = statusMap[d.status] || statusMap['unverified'];
  document.getElementById('eligStatusBadge').innerHTML =
    '<span class="status-badge ' + cls + '">' + icon + ' ' + label + '</span>';

  // Timestamp
  const ts = new Date(d.checked_at);
  document.getElementById('eligTimestamp').textContent = 'Checked ' + ts.toLocaleString();

  // Result grid
  const items = [
    ['Plan Name', d.plan_name || '—'],
    ['Group Number', d.group_number || '—'],
    ['Deductible Total', fmt$(d.deductible_total_cents)],
    ['Deductible Remaining', fmt$(d.deductible_remaining_cents)],
    ['Copay' + (d.cpt_code ? ' (' + d.cpt_code + ')' : ''), d.copay_cents !== null ? fmt$(d.copay_cents) : '—'],
    ['Coinsurance' + (d.cpt_code ? ' (' + d.cpt_code + ')' : ''), d.coinsurance_pct !== null ? d.coinsurance_pct + '%' : '—'],
    ['Prior Auth Required', d.prior_auth_required || '—'],
    ['Timely Filing Limit', d.timely_filing_limit || '—'],
  ];
  document.getElementById('eligResultGrid').innerHTML = items.map(([lbl, val]) =>
    '<div class="result-item"><div class="ri-label">' + lbl + '</div><div class="ri-val">' + val + '</div></div>'
  ).join('');

  panel.scrollIntoView({behavior: 'smooth', block: 'start'});
}
</script>
<script>navigator.sendBeacon("/api/_ping");</script>
</body></html>`);
});

app.post("/api/eligibility/check", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  if (isReadOnly(user)) return c.json({ error: "View only — contact your Admin to request access" }, 403);

  // Check plan — growth+ required
  const userRow = await c.env.DB.prepare("SELECT plan FROM users WHERE id = ?")
    .bind(user.user_id).first<{ plan: string | null }>();
  const plan = (userRow?.plan || "").toLowerCase();
  const isGrowthPlus = plan === "growth" || plan === "professional" || plan === "pro";
  if (!isGrowthPlus) return c.json({ error: "Upgrade to Growth or Professional to use Eligibility Verification" }, 403);

  let body: { first_name: string; last_name: string; dob: string; member_id: string; payer: string; npi: string; cpt_code?: string | null };
  try { body = await c.req.json(); } catch { return c.json({ error: "Invalid request" }, 400); }

  const { first_name, last_name, dob, member_id, payer, npi, cpt_code } = body;
  if (!first_name || !last_name || !dob || !member_id || !payer || !npi) {
    return c.json({ error: "Missing required fields" }, 400);
  }
  if (!PAYERS.includes(payer)) return c.json({ error: "Invalid payer" }, 400);

  // === INTEGRATION POINT ===
  // TODO: When Availity or Change Healthcare credentials are available, replace
  // the demo block below with a real API call:
  //
  // Availity REST API (OAuth2 Client Credentials):
  //   POST https://api.availity.com/availity/v1/coverages
  //   Auth: Bearer token from https://api.availity.com/availity/v1/token
  //   Body: { subscriberId, firstName, lastName, birthDate, npi, serviceTypes, payerId }
  //
  // Change Healthcare / Optum Eligibility API:
  //   POST https://apigw.changehealthcare.com/medicalnetwork/eligibility/v3
  //   Auth: Bearer token from /apigw/security/v1/token
  //   Body: X12 270 transaction wrapped in JSON
  //
  // Neither provider offers public sandbox credentials; enterprise approval required.
  // Contact: partnermanagement@availity.com or your Optum account rep.

  const result = demoEligibilityResult(payer, member_id, cpt_code || null);

  // Save de-identified record to history
  const checkId = generateId();
  const memberLast4 = member_id.slice(-4);
  await c.env.DB.prepare(
    "INSERT INTO eligibility_checks (id, user_id, member_id_last4, payer, cpt_code, result_status, result_json, created_at) VALUES (?,?,?,?,?,?,?,unixepoch())"
  ).bind(checkId, user.user_id, memberLast4, payer, cpt_code || null, result.status as string, JSON.stringify(result)).run().catch(() => {});

  return c.json(result);
});

// ─── Team Management ──────────────────────────────────────────────────────────

const TEAM_STYLES = `
.team-card{background:#fff;border-radius:16px;box-shadow:0 2px 20px rgba(0,0,0,.07);padding:2rem;margin-bottom:1.5rem}
.team-table{width:100%;border-collapse:collapse;font-size:.93rem}
.team-table th{padding:.75rem 1rem;text-align:left;background:#0f172a;color:rgba(255,255,255,.85);font-size:.73rem;text-transform:uppercase;letter-spacing:.6px;font-weight:600}
.team-table td{padding:.85rem 1rem;border-bottom:1px solid #f1f5f9;color:#334155;vertical-align:middle}
.team-table tr:last-child td{border-bottom:none}
.team-table tr:hover td{background:#f8fafc}
.role-badge{display:inline-block;padding:.2rem .65rem;border-radius:20px;font-size:.73rem;font-weight:700;text-transform:capitalize}
.role-owner{background:#fef3c7;color:#92400e;border:1px solid #fcd34d}
.role-admin{background:#dbeafe;color:#1e40af;border:1px solid #93c5fd}
.role-biller{background:#dcfce7;color:#166534;border:1px solid #86efac}
.role-readonly{background:#f1f5f9;color:#475569;border:1px solid #cbd5e1}
.seats-bar{background:#f1f5f9;border-radius:8px;height:10px;margin-top:.5rem;overflow:hidden}
.seats-fill{height:100%;background:linear-gradient(90deg,var(--electric-blue),var(--electric-teal));border-radius:8px;transition:width .4s}
.invite-form-row{display:flex;gap:.75rem;align-items:flex-end;flex-wrap:wrap}
.invite-form-row input,.invite-form-row select{flex:1;min-width:180px;padding:.65rem .9rem;border:1.5px solid #e2e8f0;border-radius:8px;font-size:.93rem;color:#0f172a;background:#fff}
.invite-form-row input:focus,.invite-form-row select:focus{outline:none;border-color:var(--electric-blue)}
.remove-btn{background:none;border:1.5px solid #fca5a5;color:#dc2626;border-radius:6px;padding:.35rem .85rem;font-size:.82rem;font-weight:600;cursor:pointer;transition:all .2s}
.remove-btn:hover{background:#fef2f2}
`;

app.get("/settings/team", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.redirect("/login?next=/settings/team");

  // Non-Professional users see upgrade prompt
  if (!isProfessionalPlan(user)) {
    return c.html(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Team Seats — ClinicOS AI</title><style>${SHARED_STYLES}${TEAM_STYLES}</style></head><body>
${buildNav(user)}
<main style="max-width:640px;margin:4rem auto;padding:0 1.5rem">
  <div class="team-card" style="text-align:center;padding:3rem 2rem">
    <div style="font-size:3rem;margin-bottom:1rem">&#x1F465;</div>
    <h2 style="font-size:1.5rem;font-weight:700;color:#0f172a;margin-bottom:.75rem">Team Seats — Professional Plan Feature</h2>
    <p style="color:#64748b;font-size:.97rem;margin-bottom:1.5rem">Team seats are a Professional plan feature. Upgrade to add your billing team and collaborate on claims, appeals, and eligibility checks — all in one shared workspace.</p>
    <a href="/pricing" style="display:inline-block;padding:.75rem 2rem;background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));color:#fff;border-radius:10px;font-weight:700;font-size:1rem;text-decoration:none">Upgrade to Professional &#x2192;</a>
  </div>
</main>
${FOOTER}<script>navigator.sendBeacon("/api/_ping");</script></body></html>`);
  }

  // Owner/Admin only
  if (!canManageTeam(user)) {
    return c.html(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Team — ClinicOS AI</title><style>${SHARED_STYLES}${TEAM_STYLES}</style></head><body>
${buildNav(user)}
<main style="max-width:640px;margin:4rem auto;padding:0 1.5rem">
  <div class="team-card" style="text-align:center;padding:3rem 2rem">
    <div style="font-size:2.5rem;margin-bottom:1rem">&#x1F512;</div>
    <h2 style="font-size:1.3rem;font-weight:700;color:#0f172a;margin-bottom:.75rem">Access Restricted</h2>
    <p style="color:#64748b;font-size:.95rem">Only Owners and Admins can manage the team. Contact your Admin for access changes.</p>
  </div>
</main>
${FOOTER}<script>navigator.sendBeacon("/api/_ping");</script></body></html>`);
  }

  // Ensure owner has an account_id
  const acctId = user.account_id ?? user.user_id;
  if (!user.account_id) {
    await c.env.DB.prepare("UPDATE users SET account_id = ?, role = 'owner' WHERE id = ? AND account_id IS NULL")
      .bind(acctId, user.user_id).run().catch(() => {});
  }

  const SEAT_LIMIT = 5;

  // Load all team members
  const members = await c.env.DB.prepare(
    "SELECT id, email, name, role, created_at FROM users WHERE account_id = ? ORDER BY created_at ASC"
  ).bind(acctId).all<{ id: string; email: string; name: string | null; role: string | null; created_at: number }>();
  const memberList = members.results || [];

  // Load pending invites
  const now = Math.floor(Date.now() / 1000);
  const invites = await c.env.DB.prepare(
    "SELECT id, invited_email, role, expires_at, accepted FROM team_invites WHERE account_id = ? AND accepted = 0 ORDER BY created_at DESC"
  ).bind(acctId).all<{ id: string; invited_email: string; role: string; expires_at: number; accepted: number }>();
  const pendingInvites = (invites.results || []).filter(i => i.expires_at > now);

  const seatsUsed = memberList.length;
  const seatsFull = seatsUsed >= SEAT_LIMIT;
  const seatsPct = Math.round((seatsUsed / SEAT_LIMIT) * 100);

  const errorMsg = c.req.query("error") || "";
  const successMsg = c.req.query("success") || "";

  const memberRows = memberList.map(m => {
    const isMe = m.id === user.user_id;
    const isOwner = (m.role || "").toLowerCase() === "owner";
    const roleBadgeClass = `role-${(m.role || "readonly").toLowerCase().replace("-only","only")}`;
    const date = new Date(m.created_at * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
    return `<tr>
      <td><strong>${escHtml(m.name || "—")}</strong>${isMe ? ' <span style="font-size:.75rem;color:#94a3b8">(you)</span>' : ''}</td>
      <td style="color:#64748b">${escHtml(m.email)}</td>
      <td><span class="role-badge ${roleBadgeClass}">${escHtml(m.role || "—")}</span></td>
      <td style="color:#94a3b8;font-size:.85rem">${escHtml(date)}</td>
      <td>${isOwner || isMe ? '<span style="color:#94a3b8;font-size:.82rem">—</span>' : `<form method="POST" action="/api/team/remove" style="margin:0"><input type="hidden" name="user_id" value="${escHtml(m.id)}"><button type="submit" class="remove-btn" onclick="return confirm('Remove this team member?')">Remove</button></form>`}</td>
    </tr>`;
  }).join("");

  const pendingRows = pendingInvites.length ? pendingInvites.map(inv => `
    <tr>
      <td colspan="2" style="color:#64748b">${escHtml(inv.invited_email)} <span style="background:#fef3c7;color:#92400e;padding:.15rem .5rem;border-radius:10px;font-size:.72rem;font-weight:700">Pending</span></td>
      <td><span class="role-badge role-${escHtml(inv.role)}">${escHtml(inv.role)}</span></td>
      <td style="color:#94a3b8;font-size:.85rem">Invite expires ${new Date(inv.expires_at * 1000).toLocaleDateString("en-US",{month:"short",day:"numeric"})}</td>
      <td><form method="POST" action="/api/team/revoke-invite" style="margin:0"><input type="hidden" name="invite_id" value="${escHtml(inv.id)}"><button type="submit" class="remove-btn">Revoke</button></form></td>
    </tr>`).join("") : '';

  const inviteFormOrFull = seatsFull
    ? `<div style="background:#f8fafc;border:1.5px solid #e2e8f0;border-radius:10px;padding:1.25rem;color:#64748b;font-size:.95rem;text-align:center">&#x1F6AB; Team is full (${SEAT_LIMIT}/${SEAT_LIMIT} seats used). Remove a member to invite someone new.</div>`
    : `<form method="POST" action="/api/team/invite">
        <div class="invite-form-row">
          <div style="flex:2;min-width:220px">
            <label style="display:block;font-size:.82rem;font-weight:600;color:#475569;margin-bottom:.35rem">Email address</label>
            <input type="email" name="email" required placeholder="colleague@practice.com" style="width:100%;box-sizing:border-box">
          </div>
          <div style="flex:1;min-width:160px">
            <label style="display:block;font-size:.82rem;font-weight:600;color:#475569;margin-bottom:.35rem">Role</label>
            <select name="role" style="width:100%;box-sizing:border-box">
              <option value="admin">Admin</option>
              <option value="biller" selected>Biller</option>
              <option value="readonly">Read-only</option>
            </select>
          </div>
          <div style="flex:0 0 auto;padding-top:1.4rem">
            <button type="submit" class="btn btn-primary" style="padding:.65rem 1.4rem;font-size:.92rem">Send Invite &#x2709;&#xFE0F;</button>
          </div>
        </div>
      </form>`;

  return c.html(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Team — ClinicOS AI</title><style>${SHARED_STYLES}${TEAM_STYLES}</style></head><body>
${buildNav(user)}
<main style="max-width:820px;margin:2.5rem auto;padding:0 1.5rem">
  <div style="margin-bottom:1.5rem">
    <h1 style="font-size:1.75rem;font-weight:800;color:#0f172a;margin-bottom:.3rem">&#x1F465; Team Management</h1>
    <p style="color:#64748b;font-size:.95rem">Manage who has access to your ClinicOS AI practice account.</p>
  </div>

  ${errorMsg ? `<div style="background:#fef2f2;border:1.5px solid #fca5a5;border-radius:10px;padding:1rem 1.25rem;color:#991b1b;margin-bottom:1.25rem;font-size:.93rem">&#x274C; ${escHtml(errorMsg)}</div>` : ''}
  ${successMsg ? `<div style="background:#f0fdf4;border:1.5px solid #86efac;border-radius:10px;padding:1rem 1.25rem;color:#166534;margin-bottom:1.25rem;font-size:.93rem">&#x2705; ${escHtml(successMsg)}</div>` : ''}

  <div class="team-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem;flex-wrap:wrap;gap:.75rem">
      <div>
        <h2 style="font-size:1.1rem;font-weight:700;color:#0f172a;margin:0 0 .2rem">Team Members</h2>
        <p style="color:#64748b;font-size:.88rem;margin:0">${seatsUsed} / ${SEAT_LIMIT} seats used</p>
        <div class="seats-bar" style="width:200px"><div class="seats-fill" style="width:${seatsPct}%"></div></div>
      </div>
    </div>
    <div style="overflow-x:auto;border-radius:10px;border:1px solid #e2e8f0;margin-bottom:1.5rem">
      <table class="team-table">
        <thead><tr>
          <th>Name</th><th>Email</th><th>Role</th><th>Joined</th><th>Action</th>
        </tr></thead>
        <tbody>${memberRows}${pendingRows}</tbody>
      </table>
    </div>
    <div>
      <h3 style="font-size:1rem;font-weight:700;color:#0f172a;margin:0 0 1rem">Invite Team Member</h3>
      ${inviteFormOrFull}
    </div>
  </div>

  <div class="team-card" style="background:#f8fafc">
    <h3 style="font-size:1rem;font-weight:700;color:#0f172a;margin:0 0 .75rem">&#x1F4CB; Role Permissions</h3>
    <table style="width:100%;border-collapse:collapse;font-size:.88rem">
      <thead><tr>
        <th style="text-align:left;padding:.5rem .75rem;color:#64748b;font-weight:600;border-bottom:1px solid #e2e8f0">Permission</th>
        <th style="text-align:center;padding:.5rem;color:#92400e;font-weight:600;border-bottom:1px solid #e2e8f0">Owner</th>
        <th style="text-align:center;padding:.5rem;color:#1e40af;font-weight:600;border-bottom:1px solid #e2e8f0">Admin</th>
        <th style="text-align:center;padding:.5rem;color:#166534;font-weight:600;border-bottom:1px solid #e2e8f0">Biller</th>
        <th style="text-align:center;padding:.5rem;color:#475569;font-weight:600;border-bottom:1px solid #e2e8f0">Read-only</th>
      </tr></thead>
      <tbody>
        ${[
          ["View claim history &amp; reports","✅","✅","✅","✅"],
          ["View denial tracker","✅","✅","✅","✅"],
          ["View appeal letters","✅","✅","✅","✅"],
          ["Run claim scrubber","✅","✅","✅","❌"],
          ["Add denial entries","✅","✅","✅","❌"],
          ["Generate appeal letters","✅","✅","✅","❌"],
          ["Run eligibility checks","✅","✅","✅","❌"],
          ["Invite &amp; remove members","✅","✅","❌","❌"],
          ["Change member roles","✅","✅","❌","❌"],
        ].map(([perm,...vals]) => `<tr>
          <td style="padding:.5rem .75rem;color:#334155;border-bottom:1px solid #f1f5f9">${perm}</td>
          ${vals.map(v => `<td style="text-align:center;padding:.5rem;border-bottom:1px solid #f1f5f9;font-size:1rem">${v}</td>`).join('')}
        </tr>`).join('')}
      </tbody>
    </table>
  </div>
</main>
${FOOTER}<script>navigator.sendBeacon("/api/_ping");</script></body></html>`);
});

app.post("/api/team/invite", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.redirect("/login");
  if (!isProfessionalPlan(user)) return c.redirect("/settings/team?error=Professional+plan+required");
  if (!canManageTeam(user)) return c.redirect("/settings/team?error=Only+Owners+and+Admins+can+invite+team+members");

  const form = await c.req.formData();
  const invitedEmail = ((form.get("email") as string) || "").trim().toLowerCase();
  const role = ((form.get("role") as string) || "biller").trim().toLowerCase();

  if (!invitedEmail || !invitedEmail.includes("@")) return c.redirect("/settings/team?error=Valid+email+required");
  const validRoles = ["admin", "biller", "readonly"];
  if (!validRoles.includes(role)) return c.redirect("/settings/team?error=Invalid+role");

  const acctId = user.account_id ?? user.user_id;
  // Ensure owner has account_id set
  if (!user.account_id) {
    await c.env.DB.prepare("UPDATE users SET account_id = ?, role = 'owner' WHERE id = ? AND account_id IS NULL")
      .bind(acctId, user.user_id).run().catch(() => {});
  }

  // Check seat limit
  const countRow = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM users WHERE account_id = ?").bind(acctId).first<{ cnt: number }>();
  if ((countRow?.cnt ?? 0) >= 5) return c.redirect("/settings/team?error=Team+is+full+(5%2F5+seats)");

  // Check if user already on this account
  const existing = await c.env.DB.prepare("SELECT id, account_id FROM users WHERE email = ?").bind(invitedEmail).first<{ id: string; account_id: string | null }>();
  if (existing && existing.account_id === acctId) {
    return c.redirect("/settings/team?error=That+user+is+already+on+your+team");
  }

  // Check for existing pending invite
  const nowTs = Math.floor(Date.now() / 1000);
  const existingInvite = await c.env.DB.prepare(
    "SELECT id FROM team_invites WHERE account_id = ? AND invited_email = ? AND accepted = 0 AND expires_at > ?"
  ).bind(acctId, invitedEmail, nowTs).first<{ id: string }>();
  if (existingInvite) return c.redirect("/settings/team?error=An+invite+for+that+email+is+already+pending");

  // Generate invite token
  const tokenBytes = new Uint8Array(32);
  crypto.getRandomValues(tokenBytes);
  const token = Array.from(tokenBytes).map(b => b.toString(16).padStart(2, "0")).join("");
  const tokenHash = await hashToken(token);
  const inviteId = generateId();
  const expiresAt = nowTs + 72 * 3600;

  await c.env.DB.prepare(
    "INSERT INTO team_invites (id, account_id, invited_email, role, token_hash, accepted, expires_at) VALUES (?, ?, ?, ?, ?, 0, ?)"
  ).bind(inviteId, acctId, invitedEmail, role, tokenHash, expiresAt).run();

  // Get owner/practice info
  const ownerRow = await c.env.DB.prepare("SELECT email, name FROM users WHERE id = ?").bind(user.user_id).first<{ email: string; name: string | null }>();
  const practiceName = ownerRow?.name || ownerRow?.email || "your practice";
  const inviterName = ownerRow?.name || ownerRow?.email || user.email;
  const acceptLink = `${c.env.APP_BASE_URL}/accept-invite?token=${token}`;
  const roleLabel = role === "readonly" ? "Read-only" : role.charAt(0).toUpperCase() + role.slice(1);

  // Send invite email
  const emailBody = `Hi,

You've been invited to join ${practiceName} on ClinicOS AI as a ${roleLabel}.

Invited by: ${inviterName}
Your role: ${roleLabel}

Click the link below to accept and set up your account:

${acceptLink}

This invite link expires in 72 hours.

If you weren't expecting this invite, you can safely ignore this email.

— The ClinicOS AI Team`;

  await fetch(`${c.env.LAUNCHYARD_API_BASE_URL}/v1/public/companies/${c.env.COMPANY_ID}/emails`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${c.env.LAUNCHYARD_API_KEY}` },
    body: JSON.stringify({
      to: invitedEmail,
      subject: `You've been invited to join ${practiceName} on ClinicOS AI`,
      body: emailBody,
      message_scope: "transactional",
    }),
  }).catch(() => {});

  return c.redirect("/settings/team?success=Invite+sent+to+" + encodeURIComponent(invitedEmail));
});

app.post("/api/team/remove", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.redirect("/login");
  if (!isProfessionalPlan(user) || !canManageTeam(user)) return c.redirect("/settings/team?error=Permission+denied");

  const form = await c.req.formData();
  const targetId = (form.get("user_id") as string || "").trim();
  if (!targetId) return c.redirect("/settings/team?error=Invalid+request");

  const acctId = user.account_id ?? user.user_id;
  // Can't remove owner
  const targetRow = await c.env.DB.prepare("SELECT role, account_id FROM users WHERE id = ?").bind(targetId).first<{ role: string | null; account_id: string | null }>();
  if (!targetRow || targetRow.account_id !== acctId) return c.redirect("/settings/team?error=User+not+found+on+your+team");
  if ((targetRow.role || "").toLowerCase() === "owner") return c.redirect("/settings/team?error=Cannot+remove+the+owner");

  await c.env.DB.prepare("UPDATE users SET account_id = NULL, role = NULL WHERE id = ?").bind(targetId).run();
  return c.redirect("/settings/team?success=Team+member+removed");
});

app.post("/api/team/revoke-invite", async (c) => {
  const user = await getCurrentUser(c);
  if (!user || !canManageTeam(user)) return c.redirect("/settings/team?error=Permission+denied");

  const form = await c.req.formData();
  const inviteId = (form.get("invite_id") as string || "").trim();
  const acctId = user.account_id ?? user.user_id;
  await c.env.DB.prepare("DELETE FROM team_invites WHERE id = ? AND account_id = ?").bind(inviteId, acctId).run().catch(() => {});
  return c.redirect("/settings/team?success=Invite+revoked");
});

// ─── Accept Invite ────────────────────────────────────────────────────────────

app.get("/accept-invite", async (c) => {
  const token = c.req.query("token") || "";
  if (!token) return c.html(inviteErrorPage("Missing invite token. Check your email for the correct link."));

  const tokenHash = await hashToken(token);
  const nowTs = Math.floor(Date.now() / 1000);
  const invite = await c.env.DB.prepare(
    "SELECT id, account_id, invited_email, role, accepted, expires_at FROM team_invites WHERE token_hash = ?"
  ).bind(tokenHash).first<{ id: string; account_id: string; invited_email: string; role: string; accepted: number; expires_at: number }>();

  if (!invite) return c.html(inviteErrorPage("This invite link is invalid. Ask your team Admin to send a new one."));
  if (invite.accepted) return c.html(inviteErrorPage("This invite has already been accepted."));
  if (invite.expires_at < nowTs) return c.html(inviteErrorPage("This invite link has expired. Ask your team Admin to send a new one."));

  // Get practice info
  const ownerRow = await c.env.DB.prepare("SELECT email, name FROM users WHERE id = ? AND (role = 'owner' OR account_id = id)").bind(invite.account_id).first<{ email: string; name: string | null }>();
  const practiceName = ownerRow?.name || ownerRow?.email || "your practice";
  const roleLabel = invite.role === "readonly" ? "Read-only" : invite.role.charAt(0).toUpperCase() + invite.role.slice(1);

  // Check if the email already has an account
  const existingUser = await c.env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(invite.invited_email).first<{ id: string }>();

  if (existingUser) {
    // Existing user: just link them
    return c.html(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Accept Invite — ClinicOS AI</title><style>${SHARED_STYLES}${AUTH_STYLES}</style></head><body>${buildNav(null)}
<main style="max-width:480px;margin:3rem auto;padding:0 1.5rem">
  <div class="auth-card" style="text-align:center">
    <div style="font-size:2.5rem;margin-bottom:.75rem">&#x1F465;</div>
    <h1 style="font-size:1.4rem;font-weight:800;color:#0f172a;margin-bottom:.5rem">Join ${escHtml(practiceName)}</h1>
    <p style="color:#64748b;font-size:.95rem;margin-bottom:1.5rem">You already have a ClinicOS AI account. Click below to join as a <strong>${escHtml(roleLabel)}</strong>.</p>
    <form method="POST" action="/accept-invite">
      <input type="hidden" name="token" value="${escHtml(token)}">
      <button type="submit" class="btn btn-primary" style="width:100%;padding:.85rem;font-size:1rem">Accept Invitation &#x2713;</button>
    </form>
  </div>
</main>
${FOOTER}</body></html>`);
  }

  return c.html(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Accept Invite — ClinicOS AI</title><style>${SHARED_STYLES}${AUTH_STYLES}</style></head><body>${buildNav(null)}
<main style="max-width:480px;margin:3rem auto;padding:0 1.5rem">
  <div class="auth-card">
    <div style="text-align:center;margin-bottom:1.5rem">
      <div style="font-size:2.5rem;margin-bottom:.75rem">&#x1F465;</div>
      <h1 style="font-size:1.4rem;font-weight:800;color:#0f172a;margin-bottom:.3rem">Join ${escHtml(practiceName)}</h1>
      <p style="color:#64748b;font-size:.9rem">You've been invited as a <strong>${escHtml(roleLabel)}</strong>. Set your name and password to get started.</p>
    </div>
    <form method="POST" action="/accept-invite">
      <input type="hidden" name="token" value="${escHtml(token)}">
      <div class="form-group">
        <label class="form-label" for="name">Your name</label>
        <input id="name" name="name" type="text" required placeholder="Jane Smith" class="form-input" autocomplete="name">
      </div>
      <div class="form-group">
        <label class="form-label" for="password">Password</label>
        <input id="password" name="password" type="password" required placeholder="Choose a secure password" class="form-input" autocomplete="new-password" minlength="8">
      </div>
      <div class="form-group" style="margin-bottom:1.5rem">
        <label class="form-label" for="password2">Confirm password</label>
        <input id="password2" name="password2" type="password" required placeholder="Repeat your password" class="form-input" autocomplete="new-password">
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%;padding:.85rem;font-size:1rem">Create Account &amp; Join &#x2713;</button>
    </form>
  </div>
</main>
${FOOTER}</body></html>`);
});

app.post("/accept-invite", async (c) => {
  const form = await c.req.formData();
  const token = (form.get("token") as string || "").trim();
  const name = (form.get("name") as string || "").trim();
  const password = (form.get("password") as string || "").trim();
  const password2 = (form.get("password2") as string || "").trim();

  if (!token) return c.html(inviteErrorPage("Missing invite token."));
  const tokenHash = await hashToken(token);
  const nowTs = Math.floor(Date.now() / 1000);
  const invite = await c.env.DB.prepare(
    "SELECT id, account_id, invited_email, role, accepted, expires_at FROM team_invites WHERE token_hash = ?"
  ).bind(tokenHash).first<{ id: string; account_id: string; invited_email: string; role: string; accepted: number; expires_at: number }>();

  if (!invite) return c.html(inviteErrorPage("Invalid invite token."));
  if (invite.accepted) return c.html(inviteErrorPage("This invite has already been accepted."));
  if (invite.expires_at < nowTs) return c.html(inviteErrorPage("This invite link has expired. Ask your team Admin to send a new one."));

  let userId: string;
  const existingUser = await c.env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(invite.invited_email).first<{ id: string }>();

  if (existingUser) {
    userId = existingUser.id;
    // Link existing user to account
    await c.env.DB.prepare("UPDATE users SET account_id = ?, role = ? WHERE id = ?")
      .bind(invite.account_id, invite.role, userId).run();
  } else {
    // New user
    if (!password) return c.html(inviteErrorPage("Password is required."));
    if (password.length < 8) return c.html(inviteErrorPage("Password must be at least 8 characters."));
    if (password !== password2) return c.html(inviteErrorPage("Passwords do not match."));

    const salt = generateId();
    const hash = await hashPassword(password, salt);
    userId = generateId();
    await c.env.DB.prepare(
      "INSERT INTO users (id, email, name, password_hash, password_salt, plan, account_id, role) VALUES (?, ?, ?, ?, ?, (SELECT plan FROM users WHERE id = ?), ?, ?)"
    ).bind(userId, invite.invited_email, name || null, hash, salt, invite.account_id, invite.account_id, invite.role).run();
  }

  // Mark invite as accepted
  await c.env.DB.prepare("UPDATE team_invites SET accepted = 1 WHERE id = ?").bind(invite.id).run();

  // Create session
  const sessionId = generateId();
  const expiresAt = nowTs + 30 * 24 * 3600;
  await c.env.DB.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)").bind(sessionId, userId, expiresAt).run();

  return new Response(null, {
    status: 302,
    headers: {
      "Location": "/scrubber",
      "Set-Cookie": `clinicios_session=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${30 * 24 * 3600}`,
    },
  });
});

function inviteErrorPage(msg: string): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Invite Error — ClinicOS AI</title><style>${SHARED_STYLES}${AUTH_STYLES}</style></head><body>${buildNav(null)}
<main style="max-width:480px;margin:4rem auto;padding:0 1.5rem">
  <div class="auth-card" style="text-align:center">
    <div style="font-size:2.5rem;margin-bottom:.75rem">&#x26A0;&#xFE0F;</div>
    <h2 style="font-size:1.25rem;font-weight:700;color:#0f172a;margin-bottom:.75rem">Invite Link Issue</h2>
    <p style="color:#64748b;font-size:.95rem;margin-bottom:1.5rem">${escHtml(msg)}</p>
    <a href="/login" style="display:inline-block;padding:.65rem 1.5rem;background:var(--electric-blue);color:#fff;border-radius:8px;font-weight:700;font-size:.93rem;text-decoration:none">Go to Sign In</a>
  </div>
</main>
${FOOTER}</body></html>`;
}

// ─── Custom Rules ─────────────────────────────────────────────────────────────

type CustomRule = {
  id: string;
  account_id: string;
  name: string;
  payer: string;
  condition_type: string;
  condition_value: string;
  severity: string;
  custom_message: string;
  is_active: number;
  created_by: string;
  created_at: number;
};

const RULE_CONDITION_LABELS: Record<string, string> = {
  "cpt_is": "CPT code is",
  "amount_exceeds": "Amount exceeds",
  "modifier_missing": "Modifier is missing",
  "icd10_is": "ICD-10 code is",
  "units_exceed": "Units exceed",
};

const RULE_PAYER_LABELS: Record<string, string> = {
  "all": "All Payers",
  "medicare": "Medicare",
  "medicaid": "Medicaid",
  "bcbs": "Blue Cross Blue Shield",
  "uhc": "United Healthcare",
  "aetna": "Aetna",
  "cigna": "Cigna",
  "humana": "Humana",
};

function applyCustomRules(
  claims: Array<Record<string, string>>,
  rules: CustomRule[],
  appliedPayer: string
): Array<Record<string, unknown>> {
  const flags: Array<Record<string, unknown>> = [];
  if (!rules.length) return flags;
  for (let i = 0; i < claims.length; i++) {
    const row = claims[i];
    const rowNum = i + 2;
    for (const rule of rules) {
      if (!rule.is_active) continue;
      // Payer matching
      const claimPayer = (row.payer_id || row.payer || appliedPayer || "").toLowerCase();
      const rulePayer = rule.payer.toLowerCase();
      if (rulePayer !== "all") {
        // Map payer values to canonical forms for comparison
        const payerMap: Record<string, string[]> = {
          "medicare": ["medicare"],
          "medicaid": ["medicaid"],
          "bcbs": ["bcbs", "blue cross", "bluecross"],
          "uhc": ["uhc", "united", "unitedhealthcare"],
          "aetna": ["aetna"],
          "cigna": ["cigna"],
          "humana": ["humana"],
        };
        const aliases = payerMap[rulePayer] || [rulePayer];
        const payerMatchesSelected = appliedPayer !== "general" && appliedPayer === rulePayer;
        const payerMatchesClaim = aliases.some(a => claimPayer.includes(a));
        if (!payerMatchesClaim && !payerMatchesSelected) continue;
      }
      const cpt = (row.cpt_code || row.cpt || "").trim().toUpperCase();
      const icd10Raw = (row.icd10_code || row.icd10 || row.diagnosis_code || "").trim().toUpperCase();
      const modifiers = (row.modifiers || row.modifier || "").trim().toUpperCase();
      const amount = parseFloat(row.billed_amount || row.amount || row.charge || "0") || 0;
      const units = parseInt(row.units || row.quantity || "1", 10) || 1;
      const val = rule.condition_value.trim().toUpperCase();
      let matched = false;
      switch (rule.condition_type) {
        case "cpt_is":
          matched = cpt === val;
          break;
        case "amount_exceeds":
          matched = amount > (parseFloat(rule.condition_value) || 0);
          break;
        case "modifier_missing": {
          // If modifiers field is blank OR doesn't contain the modifier
          const modList = modifiers.split(/[\s,;|]+/).map(m => m.trim()).filter(Boolean);
          matched = !modList.includes(val);
          break;
        }
        case "icd10_is": {
          const icd10List = icd10Raw.split(/[\s,;|]+/).map(c => c.trim()).filter(Boolean);
          matched = icd10List.some(c => c === val || c.startsWith(val));
          break;
        }
        case "units_exceed":
          matched = units > (parseInt(rule.condition_value, 10) || 0);
          break;
      }
      if (matched) {
        const condLabel = RULE_CONDITION_LABELS[rule.condition_type] || rule.condition_type;
        const payerLabel = RULE_PAYER_LABELS[rule.payer] || rule.payer;
        flags.push({
          row_number: rowNum,
          claim_id: row.claim_id || null,
          patient_id: row.patient_id || null,
          date_of_service: row.date_of_service || null,
          cpt_code: row.cpt_code || row.cpt || null,
          issue_type: rule.name,
          severity: rule.severity,
          rule_source: "Custom Rule",
          custom_rule_name: rule.name,
          is_custom_rule: true,
          description: rule.custom_message || `${condLabel} ${rule.condition_value}${payerLabel !== "All Payers" ? ` (${payerLabel})` : ""}`,
          suggested_fix: `Review claim per custom rule: "${rule.name}". ${rule.custom_message}`,
        });
      }
    }
  }
  return flags;
}

const RULES_PAGE_STYLES = `
.rules-card{background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:2rem;margin-bottom:1.5rem;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.rules-page-header{margin-bottom:2rem}
.rules-page-header h1{font-size:1.8rem;font-weight:800;color:#0f172a;margin-bottom:.35rem}
.rules-page-header p{color:#64748b;font-size:.96rem}
.rules-form-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
@media(max-width:640px){.rules-form-grid{grid-template-columns:1fr}}
.rules-form-field{display:flex;flex-direction:column;gap:.35rem}
.rules-form-field label{font-size:.82rem;font-weight:700;color:#374151;text-transform:uppercase;letter-spacing:.4px}
.rules-form-field input,.rules-form-field select{padding:.65rem .9rem;border:1.5px solid #e2e8f0;border-radius:8px;font-size:.93rem;color:#0f172a;background:#fff;transition:border-color .2s}
.rules-form-field input:focus,.rules-form-field select:focus{outline:none;border-color:#0284c7}
.rules-full{grid-column:1/-1}
.rules-save-btn{background:linear-gradient(135deg,#0284c7,#06b6d4);color:#fff;border:none;padding:.75rem 2rem;border-radius:8px;font-size:.95rem;font-weight:700;cursor:pointer;transition:all .2s;margin-top:.5rem}
.rules-save-btn:hover{transform:translateY(-1px);box-shadow:0 8px 20px rgba(2,132,199,.3)}
.rules-save-btn:disabled{opacity:.6;cursor:not-allowed;transform:none;box-shadow:none}
.rules-table-wrap{overflow-x:auto}
.rules-table{width:100%;border-collapse:collapse;font-size:.88rem}
.rules-table th{text-align:left;padding:.65rem .85rem;font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:#64748b;border-bottom:2px solid #e2e8f0;white-space:nowrap}
.rules-table td{padding:.75rem .85rem;border-bottom:1px solid #f1f5f9;vertical-align:middle}
.rules-table tr:hover td{background:#fafbfc}
.rule-name-cell{font-weight:700;color:#0f172a;font-size:.9rem}
.rule-cond-cell{color:#475569;font-size:.87rem}
.sev-badge-custom-high{background:#fef2f2;color:#dc2626;border:1px solid #fca5a5;padding:.2rem .6rem;border-radius:20px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.3px;white-space:nowrap}
.sev-badge-custom-medium{background:#fffbeb;color:#d97706;border:1px solid #fcd34d;padding:.2rem .6rem;border-radius:20px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.3px;white-space:nowrap}
.sev-badge-custom-low{background:#fefce8;color:#ca8a04;border:1px solid #fde047;padding:.2rem .6rem;border-radius:20px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.3px;white-space:nowrap}
.rule-toggle{position:relative;display:inline-block;width:40px;height:22px;cursor:pointer}
.rule-toggle input{opacity:0;width:0;height:0;position:absolute}
.rule-toggle-slider{position:absolute;inset:0;background:#cbd5e1;border-radius:11px;transition:background .2s}
.rule-toggle-slider:before{content:'';position:absolute;width:16px;height:16px;left:3px;top:3px;background:#fff;border-radius:50%;transition:transform .2s;box-shadow:0 1px 3px rgba(0,0,0,.2)}
.rule-toggle input:checked+.rule-toggle-slider{background:#0284c7}
.rule-toggle input:checked+.rule-toggle-slider:before{transform:translateX(18px)}
.rule-delete-btn{background:none;border:1.5px solid #fca5a5;color:#dc2626;border-radius:6px;padding:.3rem .7rem;font-size:.8rem;font-weight:600;cursor:pointer;transition:all .2s;white-space:nowrap}
.rule-delete-btn:hover{background:#fef2f2}
.rules-empty{text-align:center;padding:2.5rem 1rem;color:#94a3b8;font-size:.95rem}
.rules-empty .rules-empty-icon{font-size:2.5rem;margin-bottom:.75rem}
.custom-rule-badge{display:inline-flex;align-items:center;gap:.3rem;background:#f3e8ff;color:#7c3aed;border:1px solid #c4b5fd;padding:.2rem .6rem;border-radius:20px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.3px;white-space:nowrap;margin-top:.3rem}
.rules-msg{padding:.85rem 1rem;border-radius:8px;font-size:.9rem;font-weight:600;margin-bottom:1rem}
.rules-msg-success{background:#f0fdf4;color:#166534;border:1px solid #86efac}
.rules-msg-error{background:#fef2f2;color:#dc2626;border:1px solid #fca5a5}
.settings-nav{display:flex;gap:.5rem;margin-bottom:2rem;flex-wrap:wrap}
.settings-nav a{padding:.5rem 1.1rem;border-radius:8px;font-size:.88rem;font-weight:600;text-decoration:none;color:#64748b;border:1.5px solid #e2e8f0;transition:all .2s}
.settings-nav a:hover,.settings-nav a.active{background:#0284c7;color:#fff;border-color:#0284c7}
`;

app.get("/settings/rules", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.redirect("/login?next=/settings/rules");
  if (!isProfessionalPlan(user)) {
    return c.html(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Custom Rules — ClinicOS AI</title><style>${SHARED_STYLES}${RULES_PAGE_STYLES}</style></head><body>
${buildNav(user)}
<main style="max-width:700px;margin:4rem auto;padding:0 1.5rem">
  <div class="rules-card" style="text-align:center;padding:3rem 2rem">
    <div style="font-size:3rem;margin-bottom:1rem">&#x1F6E1;&#xFE0F;</div>
    <h2 style="font-size:1.5rem;font-weight:700;color:#0f172a;margin-bottom:.75rem">Custom Denial Rules — Professional Plan Feature</h2>
    <p style="color:#64748b;font-size:.97rem;margin-bottom:.75rem;max-width:480px;margin-left:auto;margin-right:auto">Build your own claim validation rules on top of the AI scrubber. Flag specific CPT codes, modifier gaps, amount thresholds, ICD-10 codes, or unit overages — per payer — with custom messages your billing staff sees instantly.</p>
    <p style="color:#64748b;font-size:.9rem;margin-bottom:1.75rem">Upgrade to the Professional plan to unlock custom rules for your practice.</p>
    <a href="/pricing" style="display:inline-block;padding:.75rem 2rem;background:linear-gradient(135deg,#0284c7,#06b6d4);color:#fff;border-radius:8px;font-weight:700;font-size:.95rem;text-decoration:none">View Professional Plan &#x2192;</a>
  </div>
</main>
${FOOTER}</body></html>`);
  }
  const acctId = user.account_id || user.user_id;
  const msg = c.req.query("msg") || "";
  const err = c.req.query("err") || "";
  const rules = await c.env.DB.prepare(
    "SELECT * FROM custom_rules WHERE account_id = ? ORDER BY created_at ASC"
  ).bind(acctId).all<CustomRule>();
  const rulesList = rules.results || [];

  const msgHtml = msg ? `<div class="rules-msg rules-msg-success">&#x2713; ${escHtml(msg)}</div>` :
    err ? `<div class="rules-msg rules-msg-error">&#x26A0; ${escHtml(err)}</div>` : "";

  const rulesRows = rulesList.length === 0
    ? `<tr><td colspan="6"><div class="rules-empty"><div class="rules-empty-icon">&#x1F4CB;</div>No custom rules yet. Add your first rule above.</div></td></tr>`
    : rulesList.map(r => {
        const condLabel = RULE_CONDITION_LABELS[r.condition_type] || r.condition_type;
        const payerLabel = RULE_PAYER_LABELS[r.payer] || r.payer;
        const sevClass = r.severity === "High" ? "sev-badge-custom-high" : r.severity === "Low" ? "sev-badge-custom-low" : "sev-badge-custom-medium";
        const canManage = !isReadOnly(user);
        return `<tr>
          <td class="rule-name-cell">${escHtml(r.name)}</td>
          <td>${escHtml(payerLabel)}</td>
          <td class="rule-cond-cell">${escHtml(condLabel)} <strong>${escHtml(r.condition_value)}</strong></td>
          <td><span class="${sevClass}">${escHtml(r.severity)}</span></td>
          <td>
            ${canManage ? `<label class="rule-toggle" title="${r.is_active ? "Disable rule" : "Enable rule"}">
              <input type="checkbox" ${r.is_active ? "checked" : ""} onchange="toggleRule('${escHtml(r.id)}',this.checked)">
              <span class="rule-toggle-slider"></span>
            </label>` : `<span style="color:#94a3b8;font-size:.82rem">${r.is_active ? "On" : "Off"}</span>`}
          </td>
          <td>
            ${canManage ? `<button class="rule-delete-btn" onclick="deleteRule('${escHtml(r.id)}','${escHtml(r.name).replace(/'/g, "\\'")}')">&#x1F5D1; Delete</button>` : "—"}
          </td>
        </tr>`;
      }).join("");

  const payerOptions = Object.entries(RULE_PAYER_LABELS).map(([v, l]) => `<option value="${v}">${l}</option>`).join("");
  const condOptions = Object.entries(RULE_CONDITION_LABELS).map(([v, l]) => `<option value="${v}">${l}</option>`).join("");
  const canManage = !isReadOnly(user);

  return c.html(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Custom Rules — ClinicOS AI</title><style>${SHARED_STYLES}${RULES_PAGE_STYLES}</style></head><body>
${buildNav(user)}
<main style="max-width:900px;margin:2.5rem auto;padding:0 1.5rem">
  <div class="settings-nav">
    <a href="/settings/team">&#x1F465; Team</a>
    <a href="/settings/rules" class="active">&#x1F6E1; Rules</a>
  </div>
  <div class="rules-page-header">
    <h1>&#x1F6E1;&#xFE0F; Custom Denial Rules</h1>
    <p>Rules run automatically during every claim scrub for your entire team. Active rules are applied after the AI&rsquo;s built-in general and payer-specific checks.</p>
  </div>
  ${msgHtml}
  ${canManage ? `<div class="rules-card">
    <h2 style="font-size:1.1rem;font-weight:700;color:#0f172a;margin-bottom:1.25rem">&#x2795; Add Custom Rule</h2>
    <form method="POST" action="/api/rules" id="addRuleForm">
      <div class="rules-form-grid">
        <div class="rules-form-field"><label>Rule Name</label><input type="text" name="name" placeholder="e.g. Flag high-cost injections" required maxlength="120"></div>
        <div class="rules-form-field"><label>Payer</label><select name="payer">${payerOptions}</select></div>
        <div class="rules-form-field"><label>Condition</label><select name="condition_type">${condOptions}</select></div>
        <div class="rules-form-field"><label>Value</label><input type="text" name="condition_value" placeholder='e.g. "99214", "500", "GA", "M54.5", "4"' required maxlength="80"></div>
        <div class="rules-form-field"><label>Severity</label><select name="severity"><option value="High">High</option><option value="Medium" selected>Medium</option><option value="Low">Low</option></select></div>
        <div class="rules-form-field rules-full"><label>Custom Message <span style="font-weight:400;text-transform:none;color:#94a3b8">(shown to billing staff when this rule flags a claim)</span></label><input type="text" name="custom_message" placeholder='e.g. "Verify prior auth before submitting"' maxlength="300"></div>
      </div>
      <button type="submit" class="rules-save-btn" id="saveRuleBtn">&#x1F4BE; Save Rule</button>
    </form>
  </div>` : `<div style="background:#fef3c7;border:1.5px solid #f59e0b;border-radius:10px;padding:1rem 1.25rem;color:#92400e;font-size:.92rem;margin-bottom:1.5rem">&#x1F441;&#xFE0F; <strong>View only</strong> — You can see your team's custom rules but cannot add or modify them. Contact your Admin to request edit access.</div>`}
  <div class="rules-card">
    <h2 style="font-size:1.1rem;font-weight:700;color:#0f172a;margin-bottom:1.25rem">&#x1F4CB; Active Rules <span style="color:#64748b;font-weight:500;font-size:.9rem">(${rulesList.length})</span></h2>
    <div class="rules-table-wrap">
      <table class="rules-table">
        <thead><tr><th>Rule Name</th><th>Payer</th><th>Condition</th><th>Severity</th><th>Active</th><th>Actions</th></tr></thead>
        <tbody id="rulesTableBody">${rulesRows}</tbody>
      </table>
    </div>
  </div>
</main>
${FOOTER}
<script>
document.getElementById('addRuleForm')?.addEventListener('submit',function(e){
  const btn=document.getElementById('saveRuleBtn');
  btn.disabled=true;btn.textContent='Saving...';
});
async function toggleRule(id,active){
  try{
    const r=await fetch('/api/rules/'+id+'/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({active})});
    if(!r.ok)throw new Error('Failed');
  }catch(e){alert('Could not update rule. Please try again.');location.reload();}
}
async function deleteRule(id,name){
  if(!confirm('Delete rule "'+name+'"? This cannot be undone.'))return;
  try{
    const r=await fetch('/api/rules/'+id,{method:'DELETE'});
    if(!r.ok)throw new Error('Failed');
    location.reload();
  }catch(e){alert('Could not delete rule. Please try again.');}
}
</script>
</body></html>`);
});

app.post("/api/rules", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  if (!isProfessionalPlan(user)) return c.redirect("/settings/rules?err=Professional+plan+required");
  if (isReadOnly(user)) return c.redirect("/settings/rules?err=View-only+access+-+contact+your+Admin");
  const formData = await c.req.formData();
  const name = (formData.get("name") as string || "").trim();
  const payer = (formData.get("payer") as string || "all").trim();
  const condition_type = (formData.get("condition_type") as string || "").trim();
  const condition_value = (formData.get("condition_value") as string || "").trim();
  const severity = (formData.get("severity") as string || "Medium").trim();
  const custom_message = (formData.get("custom_message") as string || "").trim();
  if (!name) return c.redirect("/settings/rules?err=Rule+name+is+required");
  if (!condition_value) return c.redirect("/settings/rules?err=Condition+value+is+required");
  const validConditions = Object.keys(RULE_CONDITION_LABELS);
  if (!validConditions.includes(condition_type)) return c.redirect("/settings/rules?err=Invalid+condition+type");
  const validSeverities = ["High", "Medium", "Low"];
  if (!validSeverities.includes(severity)) return c.redirect("/settings/rules?err=Invalid+severity");
  const validPayers = Object.keys(RULE_PAYER_LABELS);
  if (!validPayers.includes(payer)) return c.redirect("/settings/rules?err=Invalid+payer");
  const acctId = user.account_id || user.user_id;
  // Cap at 50 rules per account
  const countRow = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM custom_rules WHERE account_id = ?").bind(acctId).first<{ cnt: number }>();
  if ((countRow?.cnt ?? 0) >= 50) return c.redirect("/settings/rules?err=Maximum+50+custom+rules+per+account");
  const id = generateId();
  await c.env.DB.prepare(
    "INSERT INTO custom_rules (id,account_id,name,payer,condition_type,condition_value,severity,custom_message,is_active,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,1,?,unixepoch(),unixepoch())"
  ).bind(id, acctId, name, payer, condition_type, condition_value, severity, custom_message, user.user_id).run();
  return c.redirect("/settings/rules?msg=Rule+saved+successfully");
});

app.post("/api/rules/:id/toggle", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  if (!isProfessionalPlan(user)) return c.json({ error: "Professional plan required" }, 403);
  if (isReadOnly(user)) return c.json({ error: "View-only access" }, 403);
  const ruleId = c.req.param("id");
  const acctId = user.account_id || user.user_id;
  const body = await c.req.json<{ active: boolean }>();
  const isActive = body.active ? 1 : 0;
  const row = await c.env.DB.prepare("SELECT id FROM custom_rules WHERE id = ? AND account_id = ?").bind(ruleId, acctId).first();
  if (!row) return c.json({ error: "Rule not found" }, 404);
  await c.env.DB.prepare("UPDATE custom_rules SET is_active = ?, updated_at = unixepoch() WHERE id = ?").bind(isActive, ruleId).run();
  return c.json({ ok: true });
});

app.delete("/api/rules/:id", async (c) => {
  const user = await getCurrentUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  if (!isProfessionalPlan(user)) return c.json({ error: "Professional plan required" }, 403);
  if (isReadOnly(user)) return c.json({ error: "View-only access" }, 403);
  const ruleId = c.req.param("id");
  const acctId = user.account_id || user.user_id;
  await c.env.DB.prepare("DELETE FROM custom_rules WHERE id = ? AND account_id = ?").bind(ruleId, acctId).run();
  return c.json({ ok: true });
});

// ─── Pricing Page ─────────────────────────────────────────────────────────────
app.get("/pricing", async (c) => {
  const user = await getCurrentUser(c);
  const STARTER_LINK = "https://company-builder-api-hzcthfunbq-uc.a.run.app/v1/public/checkout/01KTR8VRGZAG37J1DNPJ4P2TC2?trial_days=14";
  const GROWTH_LINK  = "https://company-builder-api-hzcthfunbq-uc.a.run.app/v1/public/checkout/01KTR8VS68PNQB21BSF4M16AQF?trial_days=14";
  const PRO_LINK     = "https://company-builder-api-hzcthfunbq-uc.a.run.app/v1/public/checkout/01KTR8VSWSFB39X1ND8K338TSZ?trial_days=14";

  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Pricing — ClinicOS AI</title>
<meta name="description" content="Simple, transparent pricing for AI-powered medical billing. Start free for 14 days — no credit card required.">
<style>
${SHARED_STYLES}
/* ── Pricing page styles ── */
.pricing-hero{background:linear-gradient(135deg,var(--navy) 0%,var(--navy-light) 100%);color:#fff;padding:5rem 2rem 4rem;text-align:center}
.pricing-hero h1{font-size:2.75rem;font-weight:800;margin-bottom:1rem;line-height:1.15}
.pricing-hero p{font-size:1.15rem;color:rgba(255,255,255,.8);max-width:560px;margin:0 auto 2rem}
.pricing-trial-note{display:inline-flex;align-items:center;gap:.5rem;background:rgba(6,182,212,.15);border:1px solid rgba(6,182,212,.35);color:var(--electric-teal);padding:.5rem 1.25rem;border-radius:20px;font-size:.9rem;font-weight:600}
.pricing-wrap{max-width:1200px;margin:0 auto;padding:3.5rem 2rem 5rem}
/* Cards row */
.pricing-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1.75rem;align-items:start}
@media(max-width:900px){.pricing-grid{grid-template-columns:1fr}}
.pc{background:#fff;border:2px solid #e2e8f0;border-radius:16px;display:flex;flex-direction:column;position:relative;transition:box-shadow .25s}
.pc:hover{box-shadow:0 16px 40px rgba(2,132,199,.1)}
.pc.featured{border-color:var(--electric-blue);box-shadow:0 12px 36px rgba(2,132,199,.18)}
.pc-badge{position:absolute;top:-14px;left:50%;transform:translateX(-50%);background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));color:#fff;padding:.35rem 1.1rem;border-radius:20px;font-size:.78rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap}
.pc-header{padding:2rem 2rem 1.5rem;text-align:center;border-bottom:1px solid #e2e8f0}
.pc-name{font-size:1.3rem;font-weight:800;color:var(--navy);margin-bottom:.35rem}
.pc-tagline{font-size:.88rem;color:var(--gray-dark);margin-bottom:1.25rem;line-height:1.5}
.pc-price{font-size:3rem;font-weight:800;color:var(--electric-blue);line-height:1}
.pc-price span{font-size:1.1rem;font-weight:600;color:var(--gray-dark)}
.pc-trial{font-size:.82rem;color:var(--gray-dark);margin-top:.4rem}
.pc-body{padding:1.5rem 2rem 2rem;flex:1;display:flex;flex-direction:column}
.pc-section-label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--electric-blue);margin:1.25rem 0 .6rem;padding-top:1rem;border-top:1px solid #f1f5f9}
.pc-section-label:first-child{margin-top:0;border-top:none;padding-top:0}
.feat-list{list-style:none;display:flex;flex-direction:column;gap:.5rem;margin:0 0 .5rem}
.feat-row{display:flex;align-items:flex-start;gap:.65rem;font-size:.9rem;line-height:1.45}
.feat-row.included{color:#1e293b}
.feat-row.locked{color:#94a3b8}
.feat-icon{flex-shrink:0;width:18px;height:18px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;margin-top:.1rem}
.feat-icon.check{background:rgba(16,185,129,.15);color:#059669}
.feat-icon.lock{background:#f1f5f9;color:#94a3b8;font-size:.65rem}
.feat-note{font-size:.78rem;color:var(--electric-teal);font-weight:600;margin-left:auto;flex-shrink:0;padding-left:.4rem}
.pc-cta{margin-top:auto;padding-top:1.75rem}
.pc-cta a{display:block;text-align:center;padding:.9rem 1.5rem;border-radius:10px;font-weight:700;font-size:.95rem;text-decoration:none;transition:all .25s}
.pc-cta a.primary{background:linear-gradient(135deg,var(--electric-blue),var(--electric-teal));color:#fff}
.pc-cta a.primary:hover{transform:translateY(-2px);box-shadow:0 12px 24px rgba(2,132,199,.35)}
.pc-cta a.secondary{background:#fff;color:var(--electric-blue);border:2px solid var(--electric-blue)}
.pc-cta a.secondary:hover{background:#f0f9ff;transform:translateY(-2px)}
.pc-cta a.loading{opacity:.65;pointer-events:none}
.pc-cta-note{text-align:center;font-size:.8rem;color:var(--gray-dark);margin-top:.6rem}
/* Compare table below cards */
.compare-wrap{margin-top:4rem}
.compare-wrap h2{text-align:center;font-size:1.75rem;font-weight:800;color:var(--navy);margin-bottom:.5rem}
.compare-wrap .compare-sub{text-align:center;color:var(--gray-dark);font-size:.95rem;margin-bottom:2rem}
.compare-table{width:100%;border-collapse:collapse;font-size:.9rem}
.compare-table thead th{padding:1rem .75rem;text-align:center;font-weight:700;color:var(--navy);border-bottom:2px solid #e2e8f0}
.compare-table thead th:first-child{text-align:left}
.compare-table thead th.th-featured{color:var(--electric-blue)}
.compare-table tbody tr:nth-child(even){background:#f8fafc}
.compare-table tbody tr.group-header td{background:linear-gradient(90deg,#f0f9ff,#fff);font-weight:700;font-size:.8rem;text-transform:uppercase;letter-spacing:.07em;color:var(--electric-blue);padding:.6rem .75rem;border-top:2px solid #e2e8f0}
.compare-table td{padding:.8rem .75rem;border-bottom:1px solid #f1f5f9;vertical-align:middle}
.compare-table td:first-child{color:#1e293b;font-weight:500}
.compare-table td.center{text-align:center}
.ct-check{color:#059669;font-size:1rem;font-weight:700}
.ct-dash{color:#94a3b8;font-size:1.1rem}
.ct-partial{color:var(--electric-blue);font-size:.82rem;font-weight:600}
/* FAQ */
.faq-section{background:var(--gray-light);padding:4rem 2rem}
.faq-inner{max-width:760px;margin:0 auto}
.faq-inner h2{font-size:1.75rem;font-weight:800;color:var(--navy);text-align:center;margin-bottom:2rem}
.faq-item{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:1.25rem 1.5rem;margin-bottom:1rem}
.faq-item h4{color:var(--navy);font-weight:700;margin-bottom:.5rem;font-size:.95rem}
.faq-item p{color:var(--gray-dark);font-size:.9rem;line-height:1.6}
/* Trust bar */
.trust-bar{background:var(--navy);color:#fff;padding:3rem 2rem;text-align:center}
.trust-bar p{font-size:1.05rem;color:rgba(255,255,255,.8);max-width:680px;margin:0 auto 1.5rem}
.trust-badges{display:flex;gap:1.5rem;justify-content:center;flex-wrap:wrap}
.trust-badge{background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);padding:.5rem 1.25rem;border-radius:20px;font-size:.85rem;color:rgba(255,255,255,.9);font-weight:600}
</style>
</head>
<body>
${buildNav(user)}

<div class="pricing-hero">
  <h1>Simple, Transparent Pricing</h1>
  <p>Every plan includes a 14-day free trial. No credit card required to start.</p>
  <div class="pricing-trial-note">&#x2713;&nbsp; Cancel anytime &nbsp;·&nbsp; HIPAA-secure &nbsp;·&nbsp; Setup in minutes</div>
</div>

<div class="pricing-wrap">
  <div class="pricing-grid">

    <!-- STARTER -->
    <div class="pc">
      <div class="pc-header">
        <div class="pc-name">Starter</div>
        <div class="pc-tagline">Try it — perfect for getting started</div>
        <div class="pc-price">$99<span>/mo</span></div>
        <div class="pc-trial">14-day free trial</div>
      </div>
      <div class="pc-body">
        <div class="pc-section-label">Claim Scrubber</div>
        <ul class="feat-list">
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>First 3 flagged results per upload <span class="feat-note">Preview</span></li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>General claim rules</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Full unlimited results</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Bulk CSV upload (10 files)</li>
        </ul>
        <div class="pc-section-label">Denial Management</div>
        <ul class="feat-list">
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Denial tracker — log &amp; pattern summary</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>6-month trend chart</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Denial rate benchmarking vs industry</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Appeal letter generator (26+ codes)</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Automated appeal tracking dashboard</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Custom denial rules</li>
        </ul>
        <div class="pc-section-label">Integrations &amp; Account</div>
        <ul class="feat-list">
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>User account + claim history</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Secure login + forgot password</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>EHR / PM direct import</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Real-time eligibility check</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Multi-user team seats</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Monthly billing health report (PDF)</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Payer-specific rule profiles</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Priority support</li>
        </ul>
        <div class="pc-cta">
          <a href="${STARTER_LINK}" class="secondary" onclick="this.classList.add('loading');this.textContent='Taking you to checkout…'">Start Free Trial</a>
          <div class="pc-cta-note">14 days free, then $99/mo</div>
        </div>
      </div>
    </div>

    <!-- GROWTH -->
    <div class="pc featured">
      <div class="pc-badge">Most Popular</div>
      <div class="pc-header">
        <div class="pc-name">Growth</div>
        <div class="pc-tagline">For one active biller who wants full tools</div>
        <div class="pc-price">$299<span>/mo</span></div>
        <div class="pc-trial">14-day free trial</div>
      </div>
      <div class="pc-body">
        <div class="pc-section-label">Everything in Starter, plus:</div>
        <div class="pc-section-label" style="border-top:none;padding-top:0;margin-top:0">Claim Scrubber</div>
        <ul class="feat-list">
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Full unlimited scrubber results — no cap</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>General claim rules</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Bulk CSV upload (10 files)</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Payer-specific rule profiles</li>
        </ul>
        <div class="pc-section-label">Denial Management</div>
        <ul class="feat-list">
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Denial tracker + 6-month trend chart</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Denial rate benchmarking vs industry</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Appeal letter generator — 26+ denial codes</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Automated appeal tracking dashboard</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Custom denial rules</li>
        </ul>
        <div class="pc-section-label">Integrations &amp; Account</div>
        <ul class="feat-list">
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>User account + claim history</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Secure login + forgot password</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>EHR / PM import — Kareo/Tebra &amp; AdvancedMD <span class="feat-note">DrChrono soon</span></li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Real-time eligibility check</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Multi-user team seats</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Monthly billing health report (PDF)</li>
          <li class="feat-row locked"><span class="feat-icon lock">&#x1F512;</span>Priority support</li>
        </ul>
        <div class="pc-cta">
          <a href="${GROWTH_LINK}" class="primary" onclick="this.classList.add('loading');this.textContent='Taking you to checkout…'">Start Free Trial</a>
          <div class="pc-cta-note">14 days free, then $299/mo</div>
        </div>
      </div>
    </div>

    <!-- PROFESSIONAL -->
    <div class="pc">
      <div class="pc-header">
        <div class="pc-name">Professional</div>
        <div class="pc-tagline">Your whole team, end-to-end</div>
        <div class="pc-price">$599<span>/mo</span></div>
        <div class="pc-trial">14-day free trial</div>
      </div>
      <div class="pc-body">
        <div class="pc-section-label">Everything in Growth, plus:</div>
        <div class="pc-section-label" style="border-top:none;padding-top:0;margin-top:0">Claim Scrubber</div>
        <ul class="feat-list">
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Full unlimited scrubber results — no cap</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Bulk claim scrubbing — 10 CSV files, consolidated report</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Payer-specific rule profiles (Medicare, Medicaid, BCBS, UHC, Aetna, Cigna, Humana)</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Custom denial rules — add your own on top of built-ins</li>
        </ul>
        <div class="pc-section-label">Denial Management</div>
        <ul class="feat-list">
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Denial tracker + 6-month trend chart</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Appeal letter generator — 26+ denial codes</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Automated appeal tracking — Sent / Approved / Denied / Pending, days outstanding</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Monthly billing health report — auto PDF on 1st of month</li>
        </ul>
        <div class="pc-section-label">Team &amp; Integrations</div>
        <ul class="feat-list">
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Multi-user team seats — up to 5 users (Admin, Biller, Read-only)</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>EHR / PM import — Kareo/Tebra &amp; AdvancedMD</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Real-time eligibility check</li>
          <li class="feat-row included"><span class="feat-icon check">&#x2713;</span>Priority support</li>
        </ul>
        <div class="pc-cta">
          <a href="${PRO_LINK}" class="secondary" onclick="this.classList.add('loading');this.textContent='Taking you to checkout…'">Start Free Trial</a>
          <div class="pc-cta-note">14 days free, then $599/mo</div>
        </div>
      </div>
    </div>

  </div><!-- /pricing-grid -->

  <!-- ── Comparison Table ── -->
  <div class="compare-wrap">
    <h2>Full Feature Comparison</h2>
    <p class="compare-sub">See exactly what's in each plan before you sign up.</p>
    <table class="compare-table">
      <thead>
        <tr>
          <th style="width:40%">Feature</th>
          <th class="center" style="width:20%">Starter<br><span style="font-weight:600;color:var(--gray-dark)">$99/mo</span></th>
          <th class="center th-featured" style="width:20%">Growth<br><span style="font-weight:600">$299/mo</span></th>
          <th class="center" style="width:20%">Professional<br><span style="font-weight:600;color:var(--gray-dark)">$599/mo</span></th>
        </tr>
      </thead>
      <tbody>
        <tr class="group-header"><td colspan="4">Claim Scrubber</td></tr>
        <tr><td>Claim scrubbing results</td><td class="center"><span class="ct-partial">3 per upload</span></td><td class="center"><span class="ct-check">Unlimited</span></td><td class="center"><span class="ct-check">Unlimited</span></td></tr>
        <tr><td>General claim rules</td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr><td>Payer-specific rule profiles (6 payers)</td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr><td>Custom denial rules</td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr><td>Bulk CSV upload (up to 10 files)</td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr class="group-header"><td colspan="4">Denial Management</td></tr>
        <tr><td>Denial tracker — log denials + pattern summary</td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr><td>6-month denial trend chart</td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr><td>Denial rate benchmarking vs industry averages</td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr><td>Appeal letter generator (26+ denial codes)</td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr><td>Automated appeal tracking dashboard</td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr><td>Monthly billing health report (auto PDF)</td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr class="group-header"><td colspan="4">Account &amp; Integrations</td></tr>
        <tr><td>User account + claim history</td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr><td>Secure login + forgot password</td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr><td>EHR / PM direct import (Kareo, AdvancedMD)</td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr><td>Real-time eligibility check</td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-check">&#x2713;</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr><td>Multi-user team seats (up to 5)</td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
        <tr><td>Priority support</td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-dash">—</span></td><td class="center"><span class="ct-check">&#x2713;</span></td></tr>
      </tbody>
    </table>
  </div>
</div><!-- /pricing-wrap -->

<!-- FAQ -->
<div class="faq-section">
  <div class="faq-inner">
    <h2>Frequently Asked Questions</h2>
    <div class="faq-item">
      <h4>How does the 14-day free trial work?</h4>
      <p>Start any plan free for 14 days — no credit card required. You get full access to every feature in your chosen tier. At the end of your trial, you'll be billed at the plan rate. Cancel any time before then and you won't be charged.</p>
    </div>
    <div class="faq-item">
      <h4>Can I switch plans later?</h4>
      <p>Yes. You can upgrade or downgrade at any time from your account settings. Upgrades take effect immediately; downgrades take effect at the next billing cycle.</p>
    </div>
    <div class="faq-item">
      <h4>Is ClinicOS AI HIPAA compliant?</h4>
      <p>Yes. We sign a Business Associate Agreement (BAA) with every subscriber and use AES-256 encryption at rest and in transit. No PHI is retained after your session ends.</p>
    </div>
    <div class="faq-item">
      <h4>What EHR and PM systems do you integrate with?</h4>
      <p>Growth and Professional plans include direct import from Kareo/Tebra and AdvancedMD today. DrChrono integration is coming soon. All plans accept manual CSV upload.</p>
    </div>
    <div class="faq-item">
      <h4>What counts as a "denial code" for the appeal generator?</h4>
      <p>The appeal generator covers the 26 most common CARC/RARC denial codes returned by Medicare, Medicaid, and major commercial payers — including CO-4, CO-5, CO-11, CO-50, CO-97, PR-1, and more. Growth and Professional subscribers see the full list and can save letters to their account.</p>
    </div>
  </div>
</div>

<!-- Trust bar -->
<div class="trust-bar">
  <p>Trusted by independent practices, solo billers, and RCM teams. HIPAA-secure. No long-term contracts.</p>
  <div class="trust-badges">
    <span class="trust-badge">&#x1F512; HIPAA Secure</span>
    <span class="trust-badge">&#x1F4C4; BAA Included</span>
    <span class="trust-badge">&#x2713; No Long-Term Contracts</span>
    <span class="trust-badge">&#x1F4DE; U.S.-Based Support</span>
  </div>
</div>

${FOOTER}
</body>
</html>`);
});

// ─── Sitemap & Robots ─────────────────────────────────────────────────────────
app.get("/sitemap.xml", (c) => c.body(
  `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://clinicosal.launchyard.app/</loc></url><url><loc>https://clinicosal.launchyard.app/pricing</loc></url><url><loc>https://clinicosal.launchyard.app/scrubber</loc></url><url><loc>https://clinicosal.launchyard.app/appeal-generator</loc></url><url><loc>https://clinicosal.launchyard.app/denial-tracker</loc></url><url><loc>https://clinicosal.launchyard.app/eligibility</loc></url><url><loc>https://clinicosal.launchyard.app/appeals</loc></url><url><loc>https://clinicosal.launchyard.app/signup</loc></url><url><loc>https://clinicosal.launchyard.app/login</loc></url></urlset>`,
  200, { "Content-Type": "application/xml" }
));
app.get("/robots.txt", (c) => c.text("User-agent: *\nAllow: /\nSitemap: https://clinicosal.launchyard.app/sitemap.xml"));

// ─── Analytics ────────────────────────────────────────────────────────────────
function _hashIP(ip: string): string {
  let h = 0;
  for (let i = 0; i < ip.length; i++) h = ((h << 5) - h + ip.charCodeAt(i)) | 0;
  return "v1:" + (h >>> 0).toString(36);
}

app.post("/api/_ping", async (c) => {
  try {
    const ipHash = _hashIP(c.req.header("cf-connecting-ip") || "unknown");
    const ua = c.req.header("user-agent") || "";
    let referrer = "";
    try { const b = await c.req.json<{ r?: string }>(); if (typeof b.r === "string") referrer = b.r; } catch { /**/ }
    if (!referrer) referrer = c.req.header("referer") || "";
    c.env.ANALYTICS.writeDataPoint({ indexes: [c.env.COMPANY_ID], blobs: [ipHash, referrer, ua], doubles: [1] });
  } catch { /**/ }
  return c.body(null, 204);
});

// ─── Reports ──────────────────────────────────────────────────────────────────

const MONTH_NAMES = ["January","February","March","April","May","June","July","August","September","October","November","December"];

const DENIAL_FIX_SUGGESTIONS: Record<string, string> = {
  "CO-4":  "Verify modifier is appropriate for CPT code before submission",
  "CO-11": "Ensure diagnosis code supports medical necessity for this procedure",
  "CO-97": "Check bundling rules — this code may be included in another service billed same day",
  "CO-45": "Bill patient for contractual adjustment amount, not payer",
  "PR-96": "Obtain prior authorization before scheduling this procedure",
};

function getDenialFixSuggestion(code: string): string {
  return DENIAL_FIX_SUGGESTIONS[code] ?? "Review payer guidelines for this denial code";
}

function getDenialDescription(code: string): string {
  const entry = DENIAL_CODES.find(d => d.code === code);
  return entry?.label ?? code;
}

interface ReportData {
  userName: string;
  month: number;
  year: number;
  // claims scrubbing
  claimsScrubbed: number;
  errorsCaught: number;
  billedAmountsProtected: number;
  // denials this month
  totalDenials: number;
  totalClaimsForDenialRate: number; // claimsScrubbed + totalDenials
  // denials last month
  lastMonthDenials: number;
  lastMonthClaims: number;
  // top 3 denial drivers
  topDenials: Array<{code: string; description: string; count: number; lostRevenue: number; fix: string}>;
  // payer performance
  payerPerformance: Array<{payer: string; claims: number; denials: number; rate: number}>;
  // appeals
  openAppeals: number;
  approvedThisMonth: number;
  recoveredRevenue: number;
  // generated at
  generatedAt: string;
}

async function gatherReportData(db: D1Database, userId: string, month: number, year: number): Promise<ReportData> {
  // Month range (inclusive)
  const monthStart = new Date(year, month - 1, 1);
  const monthEnd = new Date(year, month, 1);
  const prevMonthStart = new Date(year, month - 2, 1);
  const prevMonthEnd = monthStart;

  const toUnix = (d: Date) => Math.floor(d.getTime() / 1000);

  // User name/email
  const userRow = await db.prepare("SELECT email, name FROM users WHERE id = ?").bind(userId).first<{email: string; name: string|null}>();
  const userName = userRow?.name || userRow?.email || "Your Practice";

  // Claims scrubbed this month
  const scrubRow = await db.prepare(
    "SELECT COUNT(*) as cnt, SUM(flagged_count) as flagged, SUM(total_claims) as total FROM claim_reports WHERE user_id = ? AND created_at >= ? AND created_at < ?"
  ).bind(userId, toUnix(monthStart), toUnix(monthEnd)).first<{cnt: number; flagged: number; total: number}>();
  const claimsScrubbed = scrubRow?.total ?? 0;
  const errorsCaught = scrubRow?.flagged ?? 0;

  // Estimated revenue protected: sum billed amounts from denials for flagged claims - we approximate by using denial amounts for this month
  // Actually we'll compute from the denials table as a proxy
  const protectedRow = await db.prepare(
    "SELECT COALESCE(SUM(claim_amount),0) as total FROM denials WHERE user_id = ? AND created_at >= ? AND created_at < ?"
  ).bind(userId, toUnix(monthStart), toUnix(monthEnd)).first<{total: number}>();
  const billedAmountsProtected = protectedRow?.total ?? 0;

  // Denials this month
  const denialsThisMonth = await db.prepare(
    "SELECT denial_reason_code, denial_reason_label, claim_amount, payer FROM denials WHERE user_id = ? AND created_at >= ? AND created_at < ?"
  ).bind(userId, toUnix(monthStart), toUnix(monthEnd)).all<{denial_reason_code: string; denial_reason_label: string; claim_amount: number; payer: string}>();
  const totalDenials = denialsThisMonth.results.length;
  const totalClaimsForDenialRate = claimsScrubbed + totalDenials;

  // Denials last month
  const prevDenialsRow = await db.prepare(
    "SELECT COUNT(*) as cnt FROM denials WHERE user_id = ? AND created_at >= ? AND created_at < ?"
  ).bind(userId, toUnix(prevMonthStart), toUnix(prevMonthEnd)).first<{cnt: number}>();
  const lastMonthDenials = prevDenialsRow?.cnt ?? 0;
  const prevScrubRow = await db.prepare(
    "SELECT COALESCE(SUM(total_claims),0) as total FROM claim_reports WHERE user_id = ? AND created_at >= ? AND created_at < ?"
  ).bind(userId, toUnix(prevMonthStart), toUnix(prevMonthEnd)).first<{total: number}>();
  const lastMonthClaims = (prevScrubRow?.total ?? 0) + lastMonthDenials;

  // Top 3 denial drivers
  const denialMap = new Map<string, {count: number; revenue: number; label: string}>();
  for (const d of denialsThisMonth.results) {
    const key = d.denial_reason_code;
    const existing = denialMap.get(key) ?? {count: 0, revenue: 0, label: d.denial_reason_label};
    denialMap.set(key, {count: existing.count + 1, revenue: existing.revenue + (d.claim_amount ?? 0), label: existing.label});
  }
  const topDenials = [...denialMap.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 3)
    .map(([code, v]) => ({
      code,
      description: getDenialDescription(code) || v.label,
      count: v.count,
      lostRevenue: v.revenue,
      fix: getDenialFixSuggestion(code),
    }));

  // Payer performance
  const payerMap = new Map<string, {claims: number; denials: number}>();
  for (const d of denialsThisMonth.results) {
    const p = d.payer || "Unknown";
    const existing = payerMap.get(p) ?? {claims: 0, denials: 0};
    payerMap.set(p, {claims: existing.claims + 1, denials: existing.denials + 1});
  }
  // Also add claims scrubbed per payer if we had that data — we don't (claim_reports doesn't track per payer)
  // So payer performance is based on denial data only
  const payerPerformance = [...payerMap.entries()]
    .sort((a, b) => b[1].denials - a[1].denials)
    .map(([payer, v]) => ({
      payer,
      claims: v.claims,
      denials: v.denials,
      rate: v.claims > 0 ? Math.round((v.denials / v.claims) * 100) : 0,
    }));

  // Appeals
  const openAppealsRow = await db.prepare(
    "SELECT COUNT(*) as cnt FROM appeals_tracker WHERE user_id = ? AND status NOT IN ('Approved','Denied')"
  ).bind(userId).first<{cnt: number}>();
  const openAppeals = openAppealsRow?.cnt ?? 0;

  const approvedRow = await db.prepare(
    "SELECT COUNT(*) as cnt, COALESCE(SUM(billed_amount),0) as total FROM appeals_tracker WHERE user_id = ? AND status = 'Approved' AND resolved_at >= ? AND resolved_at < ?"
  ).bind(userId, monthStart.toISOString().slice(0, 10), monthEnd.toISOString().slice(0, 10)).first<{cnt: number; total: number}>();
  const approvedThisMonth = approvedRow?.cnt ?? 0;
  const recoveredRevenue = approvedRow?.total ?? 0;

  return {
    userName,
    month,
    year,
    claimsScrubbed,
    errorsCaught,
    billedAmountsProtected,
    totalDenials,
    totalClaimsForDenialRate,
    lastMonthDenials,
    lastMonthClaims,
    topDenials,
    payerPerformance,
    openAppeals,
    approvedThisMonth,
    recoveredRevenue,
    generatedAt: new Date().toLocaleDateString("en-US", {month: "long", day: "numeric", year: "numeric"}),
  };
}

function generateReportHTML(data: ReportData): string {
  const { month, year, userName } = data;
  const monthName = MONTH_NAMES[month - 1];

  // Denial rates
  const denialRateThis = data.totalClaimsForDenialRate > 0
    ? (data.totalDenials / data.totalClaimsForDenialRate * 100)
    : 0;
  const denialRateLast = data.lastMonthClaims > 0
    ? (data.lastMonthDenials / data.lastMonthClaims * 100)
    : 0;

  const diff = denialRateThis - denialRateLast;
  let trendArrow = '<span style="color:#6b7280">→ Flat</span>';
  if (diff < -1) trendArrow = '<span style="color:#16a34a">↓ Improved</span>';
  else if (diff > 1) trendArrow = '<span style="color:#dc2626">↑ Worsened</span>';

  // Improvement score
  let score = 5;
  const rateImproved = -diff;
  if (rateImproved > 0) score += Math.min(3, Math.floor(rateImproved));
  if (rateImproved < 0) score -= Math.min(3, Math.floor(-rateImproved));
  score += Math.min(3, data.approvedThisMonth);
  score = Math.max(0, Math.min(10, score));
  const scoreLabel = score >= 7 ? "Improving" : score >= 5 ? "Stable" : "Needs Attention";
  const scoreColor = score >= 7 ? "#16a34a" : score >= 5 ? "#d97706" : "#dc2626";

  // Recommended action
  let recommendation = "Great month — maintain your current pre-submission scrubbing routine.";
  if (data.topDenials.length > 0) {
    const top = data.topDenials[0];
    // worst payer by denial rate
    const worstPayer = data.payerPerformance.length > 0 ? data.payerPerformance[0].payer : "your top payer";
    recommendation = `Focus on ${worstPayer} ${top.code} — ${top.count} denial${top.count !== 1 ? 's' : ''} this month representing $${top.lostRevenue.toFixed(2)} in estimated lost revenue. ${top.fix}.`;
  }

  // Table rows
  const topDenialRows = data.topDenials.length > 0
    ? data.topDenials.map(d => `
      <tr>
        <td><strong>${escHtml(d.code)}</strong></td>
        <td>${escHtml(d.description)}</td>
        <td style="text-align:center">${d.count}</td>
        <td style="text-align:right">$${d.lostRevenue.toFixed(2)}</td>
        <td>${escHtml(d.fix)}</td>
      </tr>`).join('')
    : '<tr><td colspan="5" style="text-align:center;color:#6b7280;font-style:italic">No denials logged this month</td></tr>';

  const payerRows = data.payerPerformance.length > 0
    ? data.payerPerformance.map(p => `
      <tr>
        <td>${escHtml(p.payer)}</td>
        <td style="text-align:center">${p.claims}</td>
        <td style="text-align:center">${p.denials}</td>
        <td style="text-align:center">${p.rate}%</td>
      </tr>`).join('')
    : '<tr><td colspan="4" style="text-align:center;color:#6b7280;font-style:italic">No payer data this month</td></tr>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ClinicOS AI — Billing Health Report ${monthName} ${year}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:14px;color:#1e293b;background:#fff;padding:0}
  .page{max-width:800px;margin:0 auto;padding:40px 48px}
  .header{margin-bottom:28px}
  .header-top{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px}
  .brand{font-size:1.1rem;font-weight:700;color:#2563eb;letter-spacing:-.01em}
  .report-meta{text-align:right;color:#64748b;font-size:12px;line-height:1.6}
  h1{font-size:1.6rem;font-weight:800;color:#0f172a;margin-bottom:4px}
  .subtitle{color:#64748b;font-size:1rem;margin-bottom:16px}
  hr{border:none;border-top:2px solid #2563eb;margin-bottom:28px}
  .section{margin-bottom:28px;page-break-inside:avoid}
  h2{font-size:1rem;font-weight:700;color:#2563eb;text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid #e2e8f0}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:8px}
  .stat-card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 18px}
  .stat-label{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px}
  .stat-value{font-size:1.5rem;font-weight:800;color:#0f172a}
  .stat-sub{font-size:12px;color:#64748b;margin-top:2px}
  .benchmark{background:#f1f5f9;border-radius:6px;padding:10px 14px;font-size:12px;color:#475569;margin-top:8px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:#f1f5f9;color:#475569;font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.04em;padding:8px 10px;border-bottom:2px solid #e2e8f0;text-align:left}
  td{padding:8px 10px;border-bottom:1px solid #f1f5f9;vertical-align:top}
  tr:last-child td{border-bottom:none}
  .score-box{display:inline-flex;align-items:center;gap:10px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 20px}
  .score-num{font-size:2rem;font-weight:800}
  .score-label{font-size:1rem;font-weight:600}
  .recommendation{background:#eff6ff;border-left:4px solid #2563eb;padding:14px 18px;border-radius:0 8px 8px 0;font-size:13px;line-height:1.6}
  .footer{margin-top:32px;padding-top:16px;border-top:1px solid #e2e8f0;text-align:center;color:#94a3b8;font-size:11px}
  .no-print{background:#2563eb;color:#fff;border:none;padding:10px 22px;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;margin-bottom:24px;display:block}
  @media print {
    .no-print{display:none!important}
    body{padding:0}
    .page{max-width:100%;padding:28px 36px}
    .section{page-break-inside:avoid}
    h2{page-break-after:avoid}
  }
  @page{margin:16mm 12mm;size:A4}
</style>
</head>
<body>
<div class="page">
  <button class="no-print" onclick="window.print()">⬇ Save as PDF (Print → Save as PDF)</button>

  <div class="header">
    <div class="header-top">
      <div>
        <div class="brand">⚡ ClinicOS AI</div>
        <h1>Monthly Billing Health Report</h1>
        <div class="subtitle">${escHtml(monthName)} ${year} · ${escHtml(userName)}</div>
      </div>
      <div class="report-meta">
        Generated ${escHtml(data.generatedAt)}<br>
        clinicosal.launchyard.app
      </div>
    </div>
    <hr>
  </div>

  <!-- 1. Denial Rate Summary -->
  <div class="section">
    <h2>Denial Rate Summary</h2>
    <div class="grid2">
      <div class="stat-card">
        <div class="stat-label">This Month</div>
        <div class="stat-value">${denialRateThis.toFixed(1)}%</div>
        <div class="stat-sub">${data.totalDenials} denials / ${data.totalClaimsForDenialRate} total claims &nbsp; ${trendArrow}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Last Month</div>
        <div class="stat-value">${denialRateLast.toFixed(1)}%</div>
        <div class="stat-sub">${data.lastMonthDenials} denials / ${data.lastMonthClaims} total claims</div>
      </div>
    </div>
    <div class="benchmark">
      <strong>Industry Benchmarks:</strong> &nbsp;
      ✅ <strong>&lt;10%</strong> — Well-run practice &nbsp;|&nbsp;
      ⚠️ <strong>10–15%</strong> — Room for improvement &nbsp;|&nbsp;
      🔴 <strong>&gt;15%</strong> — Needs attention
    </div>
  </div>

  <!-- 2. Top Denial Drivers -->
  <div class="section">
    <h2>Top 3 Denial Drivers</h2>
    <table>
      <thead>
        <tr>
          <th>Code</th>
          <th>Description</th>
          <th style="text-align:center">Count</th>
          <th style="text-align:right">Est. Lost Revenue</th>
          <th>Fix Suggestion</th>
        </tr>
      </thead>
      <tbody>${topDenialRows}</tbody>
    </table>
  </div>

  <!-- 3. Payer Performance -->
  <div class="section">
    <h2>Payer Performance</h2>
    <table>
      <thead>
        <tr>
          <th>Payer</th>
          <th style="text-align:center">Claims</th>
          <th style="text-align:center">Denials</th>
          <th style="text-align:center">Denial Rate</th>
        </tr>
      </thead>
      <tbody>${payerRows}</tbody>
    </table>
  </div>

  <!-- 4. Claims Scrubbing Summary -->
  <div class="section">
    <h2>Claims Scrubbing Summary</h2>
    <div class="grid2">
      <div class="stat-card">
        <div class="stat-label">Claims Scrubbed</div>
        <div class="stat-value">${data.claimsScrubbed}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Errors Caught</div>
        <div class="stat-value">${data.errorsCaught}</div>
        <div class="stat-sub">Est. protected: $${data.billedAmountsProtected.toFixed(2)}</div>
      </div>
    </div>
  </div>

  <!-- 5. Appeals Summary -->
  <div class="section">
    <h2>Appeals Summary</h2>
    <div class="grid2">
      <div class="stat-card">
        <div class="stat-label">Open Appeals</div>
        <div class="stat-value">${data.openAppeals}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Approved This Month</div>
        <div class="stat-value">${data.approvedThisMonth}</div>
        <div class="stat-sub">Recovered: $${data.recoveredRevenue.toFixed(2)}</div>
      </div>
    </div>
  </div>

  <!-- 6. Improvement Score -->
  <div class="section">
    <h2>Month-over-Month Improvement Score</h2>
    <div class="score-box">
      <div class="score-num" style="color:${scoreColor}">${score}/10</div>
      <div>
        <div class="score-label" style="color:${scoreColor}">${escHtml(scoreLabel)}</div>
        <div style="font-size:12px;color:#64748b;margin-top:2px">
          Starts at 5 · ${rateImproved > 0 ? `+${Math.min(3, Math.floor(rateImproved))} denial rate improved` : rateImproved < 0 ? `${Math.max(-3, Math.floor(rateImproved))} denial rate worsened` : '±0 denial rate'} · +${Math.min(3, data.approvedThisMonth)} appeals resolved
        </div>
      </div>
    </div>
  </div>

  <!-- 7. Recommended Action -->
  <div class="section">
    <h2>Recommended Action</h2>
    <div class="recommendation">${escHtml(recommendation)}</div>
  </div>

  <div class="footer">
    Generated by ClinicOS AI &middot; clinicosal.launchyard.app &middot; ${escHtml(data.generatedAt)}
  </div>
</div>
</body>
</html>`;
}

// ─── Reports page ─────────────────────────────────────────────────────────────

app.get("/reports", async (c) => {
  const cookieHeader = c.req.header("cookie") || "";
  const cookies = parseCookies(cookieHeader);
  const user = await getSession(c.env.DB, cookies["session_id"] || "");
  if (!user) return c.redirect("/login");

  const isPro = isProfessionalPlan(user);

  // Build month options: last 12 months
  const now = new Date();
  const monthOptions: Array<{value: string; label: string}> = [];
  for (let i = 1; i <= 12; i++) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    monthOptions.push({
      value: `${d.getFullYear()}-${d.getMonth() + 1}`,
      label: `${MONTH_NAMES[d.getMonth()]} ${d.getFullYear()}`,
    });
  }

  const nav = buildNav(user);

  const proContent = `
    <div class="report-controls card">
      <h2>Generate Billing Health Report</h2>
      <p style="color:#64748b;margin-bottom:20px">Select a month to generate your full PDF billing health report.</p>
      <div class="form-row">
        <select id="monthSelect" class="form-input" style="max-width:260px">
          ${monthOptions.map(o => `<option value="${o.value}">${o.label}</option>`).join('')}
        </select>
        <button id="generateBtn" class="btn-primary" onclick="generateReport()">Generate Report</button>
      </div>
      <div id="reportStatus" style="margin-top:12px;color:#64748b;font-size:14px"></div>
    </div>
    <div id="reportFrame" style="display:none;margin-top:24px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <h3 style="margin:0;color:#0f172a">Report Preview</h3>
        <button class="btn-secondary" onclick="document.getElementById('reportIframe').contentWindow.print()">⬇ Save as PDF</button>
      </div>
      <iframe id="reportIframe" style="width:100%;height:900px;border:1px solid #e2e8f0;border-radius:8px;background:#fff"></iframe>
    </div>
    <script>
    async function generateReport() {
      const select = document.getElementById('monthSelect');
      const [year, month] = select.value.split('-');
      const btn = document.getElementById('generateBtn');
      const status = document.getElementById('reportStatus');
      btn.disabled = true;
      btn.textContent = 'Generating…';
      status.textContent = 'Pulling your data…';
      try {
        const res = await fetch('/api/reports/generate?month=' + month + '&year=' + year);
        if (!res.ok) { const t = await res.text(); throw new Error(t); }
        const html = await res.text();
        const frame = document.getElementById('reportFrame');
        const iframe = document.getElementById('reportIframe');
        frame.style.display = 'block';
        iframe.srcdoc = html;
        status.textContent = '';
        frame.scrollIntoView({behavior:'smooth'});
      } catch(e) {
        status.textContent = 'Error: ' + e.message;
      } finally {
        btn.disabled = false;
        btn.textContent = 'Generate Report';
      }
    }
    </script>`;

  const starterContent = `
    <div class="upgrade-gate card" style="text-align:center;padding:48px 32px">
      <div style="position:relative;display:inline-block;width:100%;max-width:640px">
        <div class="report-blur-preview" style="filter:blur(6px);pointer-events:none;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;background:#f8fafc;padding:32px">
          <div style="font-size:1.4rem;font-weight:800;color:#0f172a;margin-bottom:8px">Monthly Billing Health Report</div>
          <div style="color:#64748b;margin-bottom:16px">January 2025 · Sample Practice</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
            <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:12px"><div style="font-size:11px;color:#94a3b8;text-transform:uppercase">Denial Rate</div><div style="font-size:1.8rem;font-weight:800;color:#0f172a">8.3%</div></div>
            <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:12px"><div style="font-size:11px;color:#94a3b8;text-transform:uppercase">Improvement Score</div><div style="font-size:1.8rem;font-weight:800;color:#16a34a">7/10</div></div>
          </div>
          <div style="background:#eff6ff;padding:12px;border-radius:6px;font-size:12px;color:#1e40af">Top Denial Driver: CO-4 — 12 denials, $3,240 estimated lost revenue</div>
        </div>
        <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;background:rgba(255,255,255,0.85);backdrop-filter:blur(2px);border-radius:8px">
          <div style="font-size:2rem;margin-bottom:8px">🔒</div>
          <h3 style="font-size:1.2rem;font-weight:800;color:#0f172a;margin-bottom:6px">Professional Plan Required</h3>
          <p style="color:#64748b;margin-bottom:20px;font-size:14px">Monthly billing health reports are available on the Professional plan.</p>
          <a href="/pricing" class="btn-primary" style="text-decoration:none">Upgrade to Professional →</a>
        </div>
      </div>
    </div>`;

  const html = `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Billing Health Reports — ClinicOS AI</title>
<style>
:root{--electric-blue:#2563eb;--navy:#0f172a}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#f8fafc;color:#1e293b}
nav{background:#fff;border-bottom:1px solid #e2e8f0;position:sticky;top:0;z-index:100}
.nav-container{max-width:1200px;margin:0 auto;padding:0 24px;display:flex;align-items:center;justify-content:space-between;height:60px}
.logo{display:flex;align-items:center;gap:8px;font-weight:800;font-size:1.1rem;color:var(--navy);text-decoration:none}
.logo-icon{background:linear-gradient(135deg,var(--electric-blue),#06b6d4);color:#fff;width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:14px}
.nav-links{list-style:none;display:flex;align-items:center;gap:4px}
.nav-links a{text-decoration:none;color:#475569;font-size:.9rem;font-weight:500;padding:.4rem .7rem;border-radius:6px;transition:all .15s}
.nav-links a:hover{color:var(--electric-blue);background:#f0f7ff}
.nav-link-highlight{color:var(--electric-blue)!important;font-weight:600!important}
.main{max-width:900px;margin:0 auto;padding:40px 24px}
.page-title{font-size:1.8rem;font-weight:800;color:#0f172a;margin-bottom:6px}
.page-sub{color:#64748b;margin-bottom:28px}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:28px}
.form-row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.form-input{border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:14px;color:#0f172a;outline:none;transition:border-color .2s}
.form-input:focus{border-color:var(--electric-blue)}
.btn-primary{background:var(--electric-blue);color:#fff;border:none;border-radius:8px;padding:10px 22px;font-size:14px;font-weight:600;cursor:pointer;transition:background .2s;display:inline-block}
.btn-primary:hover{background:#1d4ed8}
.btn-primary:disabled{opacity:.6;cursor:not-allowed}
.btn-secondary{background:#fff;color:var(--electric-blue);border:2px solid var(--electric-blue);border-radius:8px;padding:8px 18px;font-size:13px;font-weight:600;cursor:pointer;transition:all .2s}
.btn-secondary:hover{background:#eff6ff}
</style>
</head><body>
${nav}
<div class="main">
  <div class="page-title">📊 Billing Health Reports</div>
  <div class="page-sub">Monthly summary of your practice's billing performance, denial trends, and improvement score.</div>
  ${isPro ? proContent : starterContent}
</div>
</body></html>`;

  return c.html(html);
});

app.get("/api/reports/generate", async (c) => {
  const cookieHeader = c.req.header("cookie") || "";
  const cookies = parseCookies(cookieHeader);
  const user = await getSession(c.env.DB, cookies["session_id"] || "");
  if (!user) return c.json({error: "Unauthorized"}, 401);
  if (!isProfessionalPlan(user)) return c.json({error: "Professional plan required"}, 403);

  const monthStr = c.req.query("month");
  const yearStr = c.req.query("year");
  const month = parseInt(monthStr || "");
  const year = parseInt(yearStr || "");
  if (isNaN(month) || isNaN(year) || month < 1 || month > 12 || year < 2020 || year > 2100) {
    return c.json({error: "Invalid month/year"}, 400);
  }

  const data = await gatherReportData(c.env.DB, user.user_id, month, year);
  const html = generateReportHTML(data);

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Disposition": `attachment; filename="ClinicOS-Report-${MONTH_NAMES[month-1]}-${year}.pdf"`,
    },
  });
});

// ─── Scheduled cron: send monthly reports on 1st of each month ────────────────

async function runMonthlyCron(env: Bindings): Promise<void> {
  const now = new Date();
  // We run on the 1st — send report for previous month
  const prevMonth = now.getMonth() === 0 ? 12 : now.getMonth(); // getMonth() is 0-indexed, Jan=0
  const prevYear = now.getMonth() === 0 ? now.getFullYear() - 1 : now.getFullYear();

  // Find all Professional users with activity last month
  const monthStart = new Date(prevYear, prevMonth - 1, 1);
  const monthEnd = new Date(prevYear, prevMonth, 1);
  const toUnix = (d: Date) => Math.floor(d.getTime() / 1000);

  const activeUsers = await env.DB.prepare(`
    SELECT DISTINCT u.id, u.email, u.name FROM users u
    WHERE u.plan IN ('professional','pro')
    AND (
      EXISTS(SELECT 1 FROM claim_reports cr WHERE cr.user_id = u.id AND cr.created_at >= ? AND cr.created_at < ?)
      OR
      EXISTS(SELECT 1 FROM denials d WHERE d.user_id = u.id AND d.created_at >= ? AND d.created_at < ?)
    )
  `).bind(toUnix(monthStart), toUnix(monthEnd), toUnix(monthStart), toUnix(monthEnd)).all<{id: string; email: string; name: string|null}>();

  for (const user of activeUsers.results) {
    // Check if already sent
    const alreadySent = await env.DB.prepare(
      "SELECT id FROM sent_reports WHERE user_id = ? AND month = ? AND year = ?"
    ).bind(user.id, prevMonth, prevYear).first();
    if (alreadySent) continue;

    try {
      const data = await gatherReportData(env.DB, user.id, prevMonth, prevYear);
      // We can't attach HTML as a real PDF attachment via the email API (plain text only)
      // So include a direct link to the reports page
      const monthName = MONTH_NAMES[prevMonth - 1];
      const displayName = user.name || user.email.split("@")[0];

      const emailBody = `Hi ${displayName},

Your ClinicOS AI monthly billing health report for ${monthName} ${prevYear} is ready.

Here's a quick summary:
• Denial Rate: ${data.totalClaimsForDenialRate > 0 ? (data.totalDenials / data.totalClaimsForDenialRate * 100).toFixed(1) : '0.0'}%
• Claims Scrubbed: ${data.claimsScrubbed}
• Errors Caught: ${data.errorsCaught}
• Appeals Approved This Month: ${data.approvedThisMonth} ($${data.recoveredRevenue.toFixed(2)} recovered)

Log in to ClinicOS AI to generate your full interactive report for any past month:
https://clinicosal.launchyard.app/reports

Best,
ClinicOS AI Team`;

      await fetch(`${env.LAUNCHYARD_API_BASE_URL}/v1/public/companies/${env.COMPANY_ID}/emails`, {
        method: "POST",
        headers: {"Content-Type": "application/json", "Authorization": `Bearer ${env.LAUNCHYARD_API_KEY}`},
        body: JSON.stringify({
          to: user.email,
          subject: `Your ClinicOS AI Billing Health Report — ${monthName} ${prevYear}`,
          body: emailBody,
          message_scope: "transactional",
        }),
      });

      // Mark as sent
      const sentId = generateId();
      await env.DB.prepare(
        "INSERT OR IGNORE INTO sent_reports (id, user_id, month, year) VALUES (?, ?, ?, ?)"
      ).bind(sentId, user.id, prevMonth, prevYear).run();
    } catch (err) {
      console.error(`Failed to send report for user ${user.id}:`, err);
    }
  }
}

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledEvent, env: Bindings, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runMonthlyCron(env));
  },
};

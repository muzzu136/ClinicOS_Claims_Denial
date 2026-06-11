# Company App — Engineering Agent Guide

This is a Cloudflare Worker app deployed on Launchyard. You edit code, commit, push, then call `deploy_app` to deploy.

## Architecture

- **Runtime:** Cloudflare Workers (Hono framework)
- **HTML pages:** Worker routes in `worker/src/index.ts` (e.g. `app.get("/", c => c.html(...))`). The home page is a route, not a static file.
- **API routes:** Same place — `app.get("/api/...")` etc. in `worker/src/index.ts`.
- **Static assets:** `worker/site/` is for CSS, images, favicons, `robots.txt` — served automatically at exact path (e.g. `site/styles.css` → `/styles.css`). **Don't put HTML here** (see precedence trap below).
- **Database:** Cloudflare D1 (SQLite-compatible SQL) via `c.env.DB`
- **Object storage:** Cloudflare R2 via `c.env.FILES_BUCKET`
- **Visitor analytics:** `c.env.ANALYTICS` (always available)
- **No ASSETS binding:** You cannot read files from `site/` inside a Hono handler — there is no `c.env.ASSETS` in this platform runtime.

### Precedence: static assets win over Worker routes

If a file in `site/` exact-matches a request path, the static file is served and the matching Worker route never runs. This is silent — the deploy succeeds, the healthcheck passes, but the Worker route you wrote is dead.

Practical rules:
- Put HTML pages as Worker routes, not as files in `site/`.
- If you ever need a static HTML file (e.g. a vendor verification page), pick a path that no Worker route also handles.
- If a route you wrote isn't taking effect on the live site, check whether `site/` contains a file at that exact path.

## Deployment Manifest (`worker/launchyard.manifest.json`)

This file tells the platform how to deploy your worker. **All platform resource provisioning is controlled by this file.**

### Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_version` | `1` | Yes | Always `1` |
| `runtime` | `"cloudflare_worker"` | Yes | Always `"cloudflare_worker"` |
| `entrypoint` | string | Yes | Worker entry point relative to `worker/` (e.g. `"src/index.ts"`) |
| `assets_dir` | string | No | Static assets directory (e.g. `"./site"`) |
| `healthcheck_path` | string | Yes | Path the platform GETs after deploy. Must start with `/`. Return status < 400. |
| `requested_capabilities` | object | No | Platform resources to provision (see below) |
| `requested_env` | string[] | No | Informational list of expected env vars (not enforced) |

### `requested_capabilities`

This is where you request platform-managed resources. **These must be nested inside `requested_capabilities` — NOT as top-level keys.**

```json
{
  "requested_capabilities": {
    "db": "required",
    "object_storage": "required"
  }
}
```

| Key | Value | What it provisions | Binding name |
|---|---|---|---|
| `"db"` | `"required"` | Cloudflare D1 database | `DB` (typed as `D1Database`) |
| `"object_storage"` | `"required"` | Cloudflare R2 bucket | `FILES_BUCKET` (typed as `R2Bucket`) |
| `"ai"` | `"required"` | Cloudflare Workers AI (cheap/open models) | `AI` (typed as `Ai`) |
| `"frontier_ai"` | `"required"` | Real OpenAI / Anthropic via the Launchyard proxy | _(no new binding — uses `LAUNCHYARD_API_KEY`)_ |
| `"queues"` | `"required"` | Background-job queue (+ DLQ) for slow work off the request | `JOBS_QUEUE` (producer); add a `queue` handler |
| `"cron"` | `{"schedules":["*/15 * * * *"]}` | Scheduled (UTC) Worker invocations | _(no binding — add a `scheduled` handler)_ |

**WRONG** (will NOT work):
```json
{
  "db": "required",
  "object_storage": "required"
}
```

**CORRECT:**
```json
{
  "requested_capabilities": {
    "db": "required",
    "object_storage": "required"
  }
}
```

### Forbidden keys

Never put these in the manifest — they are platform-controlled:
`worker_name`, `account_id`, `bindings`, `secret_values`, `secret_names`, `bucket_names`, `db_identifiers`, `custom_routes`, `zone_ids`, `deployment_target_urls`

## Available Bindings

Always available (no configuration needed):

| Binding | Type | Description |
|---|---|---|
| `COMPANY_ID` | `string` | Company's unique ID |
| `APP_BASE_URL` | `string` | Public URL (e.g. `https://myapp.launchyard.app`) |
| `ANALYTICS` | `AnalyticsEngineDataset` | Visitor tracking dataset |

Opt-in via `requested_capabilities`:

| Binding | Type | Capability | Description |
|---|---|---|---|
| `DB` | `D1Database` | `"db": "required"` | SQL database (SQLite-compatible). Create tables, run queries. |
| `FILES_BUCKET` | `R2Bucket` | `"object_storage": "required"` | Object storage. Upload/download files. |
| `AI` | `Ai` | `"ai": "required"` | Cloudflare Workers AI. Run text generation, embeddings, image, speech models, etc. Call the `list_ai_models` tool to see the current catalog before picking a `@cf/...` id (it rotates). Shape: `await c.env.AI.run(modelId, { messages: [...] })` for chat models, `{ prompt: "..." }` for plain text-generation. |
| _(none)_ | — | `"frontier_ai": "required"` | Real OpenAI / Anthropic via the Launchyard proxy. No new binding — point the stock SDK at the proxy with `LAUNCHYARD_API_KEY`. See "Frontier models" below. |

## Frontier models (real OpenAI / Anthropic)

When an open Workers AI model isn't good enough, request
`"frontier_ai": "required"` in the manifest and call OpenAI or Anthropic with
their **stock SDK**, pointed at the Launchyard proxy. You change exactly two
things vs. the documented SDK usage — the base URL and the API key — and use
the already-injected `LAUNCHYARD_API_KEY` (never a real provider key; the
platform injects those server-side):

```ts
// OpenAI
const openai = new OpenAI({
  baseURL: `${env.LAUNCHYARD_API_BASE_URL}/v1/ai/openai/v1`,
  apiKey: env.LAUNCHYARD_API_KEY,
});

// Anthropic
const anthropic = new Anthropic({
  baseURL: `${env.LAUNCHYARD_API_BASE_URL}/v1/ai/anthropic`,
  apiKey: env.LAUNCHYARD_API_KEY,
});
```

Everything else — request/response shapes, streaming, tool use — is exactly as
the provider documents. The proxy supports **all** inference endpoints: OpenAI
chat completions, responses, embeddings, images (generations + edits), audio
(speech/transcriptions), moderations; Anthropic messages. It does **not** proxy
account/admin surface (files, fine-tuning, batches, assistants, vector stores,
realtime — those `404`).

**Model ids rotate — don't hardcode from memory.** Look up the current id with
the `browse` CLI / provider docs before picking one. For images the current
model is `gpt-image-2`, which does **not** accept the old `gpt-image-1`
`input_fidelity` parameter (it always uses high fidelity) — passing it returns a
`400`. When a model rejects a parameter, drop it or switch to the model the
error names; don't retry the same shape.

**Budget:** each business starts with ~$5 of frontier-model budget; the founder
can top it up from the dashboard. A `402` with `code: "ai_budget_exhausted"` is
**not a bug** — the business is out of AI budget. Handle it gracefully (e.g.
show a friendly "AI temporarily unavailable" message); don't retry in a loop.
Never ask the founder for an OpenAI/Anthropic key, and never hardcode one.

**`ai` vs `frontier_ai`:** use `ai` (Workers AI) for cheap/open models;
`frontier_ai` when the task genuinely needs Claude/GPT quality.

## Background jobs & cron

The runtime kills background work (`waitUntil`) ~30s after the visitor's
request ends. For anything slower — **especially frontier image/audio
generation** — do NOT block the request or rely on `waitUntil`. Use a **queue**.

The worker entrypoint is a multi-handler object so `scheduled`/`queue` can live
next to `fetch`:

```ts
export default {
  fetch: app.fetch,
  // add these only when you request the matching capability:
  // scheduled: async (event, env, ctx) => { /* cron, UTC */ },
  // queue: async (batch, env, ctx) => { /* background jobs */ },
};
```

### Background jobs (the "submit → email later" pattern)

Request `"queues": "required"`. You get a `JOBS_QUEUE` producer binding and a
DLQ (provisioned for you). The flow:

1. The request handler writes a row (`status = 'processing'`), calls
   `await c.env.JOBS_QUEUE.send({ id, ...small ids/keys })`, and returns
   **immediately** (e.g. `{ id, status: "processing" }`). Never block the
   visitor on a slow generation.
2. The `queue(batch, env, ctx)` handler does the slow work — call the AI proxy,
   write the result to R2/D1, and **email the visitor** via the public email
   API — then `msg.ack()`. On a transient failure `msg.retry()` (it lands in
   the DLQ after the retry cap).
3. Optionally a `scheduled` cron sweep marks rows stuck in `processing` too long
   as `failed`.

**Send small messages** (ids + keys), not large payloads.

**Budget 402 in the consumer is terminal, not transient.** An AI call from the
queue consumer still debits the AI budget. If it returns `402`
`ai_budget_exhausted`, `msg.ack()` and mark the row unavailable — do NOT
`msg.retry()` (a retry storm just burns the DLQ).

### Cron

Request `"cron": { "schedules": ["*/15 * * * *"] }` and export `scheduled`.
Schedules are **5-field, UTC** (day-of-week is `1=Sunday..7=Saturday`; no
`@hourly`/`@daily` presets). Max 3 schedules.

**The deploy hard-fails** if you request `queues`/`cron` without exporting the
matching `queue`/`scheduled` handler — add the handler in the same change.

## How Deployment Works

1. You edit code, commit, and push to `main`
2. You call `deploy_app` (no arguments needed)
3. The platform reads `worker/launchyard.manifest.json`
4. The platform generates its own wrangler config — **your `wrangler.toml` is only used for local dev** (`wrangler dev`). In production, the platform ignores it except for `compatibility_date`.
5. The platform provisions any requested resources (D1 database, R2 bucket)
6. The platform runs `npm ci` and `npx wrangler deploy` with the generated config
7. The platform wires all bindings (DB, FILES_BUCKET, ANALYTICS, COMPANY_ID, APP_BASE_URL) automatically
8. The platform runs a health check against `healthcheck_path`
9. If the health check passes, the deploy succeeds and the site is live

**Do NOT:**
- Add `d1_databases`, `r2_buckets`, or other binding sections to `wrangler.toml` for production. The platform handles this.
- Put secrets or credentials in `wrangler.toml` or the manifest
- Modify the `name` field in `wrangler.toml` (it's overridden by the platform)
- **Modify or remove the `_hashIP` function or the `/api/_ping` handler.** These are platform-managed analytics infrastructure. The platform depends on the exact data format written to `ANALYTICS`. Changing the blob order, hash format, or removing the handler will break visitor tracking on the founder dashboard.

**Do:**
- Keep `wrangler.toml` for local development only
- Use `requested_capabilities` in the manifest to declare what you need
- Always include a working health check endpoint
- Do **not** add your own `<script>navigator.sendBeacon("/api/_ping")</script>` tag — the Launchyard platform automatically injects an enriched beacon into every HTML response before it reaches the visitor. Adding a second beacon just double-writes every page view and inflates the raw row count in analytics.

## D1 Database Usage

### THE RULE — read this before writing any DB code

**Never put DDL (`CREATE TABLE`, `ALTER TABLE`, `CREATE INDEX`,
`DROP …`) anywhere in `worker/src/`. Including inside template
literals. Including inside `db.prepare()`. Schema lives ONLY in
`worker/migrations/*.sql` files.**

If you put DDL in worker code, the deploy will fail with an error
like:

```
DDL found in worker source — schema lives in worker/migrations/,
not in route handlers:
  worker/src/index.ts:42  [CREATE TABLE]  await env.DB.prepare(`CREATE TABLE …
```

When you see that error, the fix is **always the same**: move the
DDL into a new migration file (`./scripts/new-migration.sh add_xyz`),
delete the inline version, redeploy. The pipeline applies pending
migrations to D1 before your worker code goes live, so by the time
any route handler runs, the schema is guaranteed to exist. Route
handlers query tables; they never create them.

### The full rules (all enforced by the deploy pipeline)

1. **New schema = new file.** When you need a new table, column, or
   index, create `worker/migrations/NNNN_description.sql` with the next
   sequence number. Never edit an existing migration file.
2. **No DDL in worker code.** See the rule above. The deploy pipeline
   greps `worker/src/**/*.ts` (including inside string and template
   literal contents) for `CREATE TABLE`, `ALTER TABLE`,
   `CREATE INDEX`, and `DROP …`. Any match fails the deploy with a
   file:line excerpt.
3. **Migrations are append-only.** Once a file is applied to prod, its
   contents are immutable. The pipeline records a checksum on apply
   and refuses future deploys if the file changed. If you got
   something wrong, write a new migration that fixes it forward.

### Adding a migration

Use the helper so sequence numbers can't collide:

```bash
./scripts/new-migration.sh add_orders_table
# creates worker/migrations/0007_add_orders_table.sql with a header
```

Then edit the file. Pure SQL — no JS. Multiple statements in one file
are fine; D1 wraps each migration in a transaction, so a partial failure
rolls the whole file back atomically.

```sql
-- worker/migrations/0007_add_orders_table.sql
CREATE TABLE orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_email TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX idx_orders_email ON orders(customer_email);
```

### What's allowed in migration files

- `CREATE TABLE`, `CREATE INDEX`, `ALTER TABLE … ADD COLUMN` — standard.
- `INSERT` for seed data, lookup tables, default config rows — fine.
- `CREATE UNIQUE INDEX` on existing data — allowed but may fail at
  apply time if existing rows violate uniqueness. That's a useful
  deploy-time signal, not a bug. The deploy will surface the failure
  loudly.
- `ALTER TABLE … ADD COLUMN … NOT NULL` without a `DEFAULT` — same
  shape: allowed but fails if the table has existing rows.
- `DROP TABLE`, `DROP COLUMN`, `ALTER TABLE … RENAME` — allowed.
  These warn in the deploy log (so the schema change leaves a
  breadcrumb) but do **not** block. Put them in a migration file like
  any other change so the sidecar tracks them — never apply schema
  changes out-of-band via `query_company_database`, which leaves the
  schema untracked and drifts on the next deploy.

### Changing a CHECK constraint or column type (SQLite recreate)

SQLite/D1 has no `ALTER … ALTER CONSTRAINT` and no `ALTER COLUMN
TYPE`. To widen a `CHECK`, change a column type, or drop a column, use
the standard SQLite recreate-table pattern in a single migration file —
it's data-preserving and fully tracked:

```sql
-- 0007_widen_species_check.sql
CREATE TABLE species_new (
  id        INTEGER PRIMARY KEY,
  edibility TEXT CHECK(edibility IN
              ('edible','poisonous','inedible','unknown'))
);
INSERT INTO species_new SELECT * FROM species;
DROP TABLE species;
ALTER TABLE species_new RENAME TO species;
-- recreate any indexes/triggers the old table had
CREATE INDEX idx_species_edibility ON species(edibility);
```

The `DROP TABLE` / `RENAME` lines warn in the deploy log; the deploy
still succeeds.

### Querying — same as before

```ts
const { results } = await c.env.DB.prepare(
  "SELECT * FROM items WHERE id = ?"
).bind(id).all();
```

### Batch writes — collapse many DML statements into one round-trip

```ts
await c.env.DB.batch([
  c.env.DB.prepare("INSERT INTO items (name) VALUES (?)").bind("foo"),
  c.env.DB.prepare("INSERT INTO items (name) VALUES (?)").bind("bar"),
]);
```

Each `db.prepare(x).run()` is one round-trip to the D1 service (~270ms
each). Use `db.batch([...])` whenever you have multiple writes — one
call is dramatically faster than a loop of `await .run()`s.

### Why this matters

Earlier versions of this template taught "create tables on first request
(idempotent)" with inline `CREATE TABLE IF NOT EXISTS`. That pattern
silently compounds: a successful app accumulates schema, and every route
ends up paying tens of seconds of round-trip overhead on cold isolates
before any real work. The migrations folder + deploy-time apply means
schema setup happens once at deploy, not on every request.

## R2 Storage Usage

Upload:
```ts
await c.env.FILES_BUCKET.put("uploads/photo.jpg", imageBytes);
```

Download:
```ts
const obj = await c.env.FILES_BUCKET.get("uploads/photo.jpg");
if (obj) return new Response(obj.body, { headers: { "Content-Type": "image/jpeg" } });
```

List:
```ts
const listed = await c.env.FILES_BUCKET.list({ prefix: "uploads/" });
```

## Common Patterns

### Serving HTML pages
HTML pages are Worker routes — same place as your API routes, in `worker/src/index.ts`:

```ts
app.get("/about", (c) => {
  return c.html(`<!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <title>About</title>
      <link rel="stylesheet" href="/styles.css" />
    </head>
    <body>
      <h1>About</h1>
    </body>
  </html>`);
});
```

This works for the home page (`/`), clean URLs (`/about`, `/pricing`), dynamic routes (`/p/:slug`), SEO pages, and SPA fallbacks. There is no `c.env.ASSETS` binding inside handlers — you cannot fetch a static `index.html` from Worker code.

### Linking to static assets
Reference files in `site/` by their public path. `site/styles.css` becomes `/styles.css`, `site/logo.png` becomes `/logo.png`. Don't try to read these files from inside a handler.

### Don't put HTML in site/
The `[assets]` binding serves static files **before** the Worker fetch handler runs. A `site/about.html` file will silently shadow any `app.get("/about.html", ...)` route at the same path. The deploy will still succeed, the healthcheck will still pass, and the Worker route will simply never fire. Keep HTML in routes; keep `site/` for CSS, images, favicons, and `robots.txt`.

## Selling things (Stripe)

LaunchYard handles all payments for you. **Do NOT integrate Stripe directly in this worker.** The seller creates products from their LaunchYard dashboard, then you wire up "Buy" links pointing at LaunchYard's hosted checkout.

### Buy button pattern

Once a product exists, link to it like this:

```html
<a href="https://api.launchyard.dev/v1/public/checkout/{product_id}?return_to=https://{your-app-domain}/thanks">
  Buy now
</a>
```

The link redirects the visitor to Stripe's hosted checkout. After payment, Stripe redirects to `return_to` (your success page). LaunchYard records the sale, holds funds for 14 days, then pays the seller out (minus a 20% platform fee) to their connected payout account.

**Always use the `api.launchyard.dev` host shown above.** Do not point buy buttons at a raw `*.run.app` Cloud Run URL.

**Do NOT append `fbclid`, `utm_*`, or any ad-tracking params to the buy link yourself.** LaunchYard injects a small script on every storefront that captures ad click-ids from the visitor's landing URL and automatically appends them to your `/v1/public/checkout/...` links at click time, so the sale is correctly attributed to the ad that drove it. Hand-rolling this would double-up or clobber it. Just render the plain buy link.

### What you should NOT do

- Do not collect card details in your worker — payments go through LaunchYard.
- Do not call the Stripe API directly — there's no Stripe key wired into your worker, by design.
- Do not store buyer payment data — LaunchYard's checkout handles all of that.
- Do not implement your own checkout flow — `?return_to=` on the LaunchYard buy link covers redirects after a successful sale.

### Where products come from

Products are created **outside your worker** — you never create one yourself. There is no product-creation endpoint in the worker context, and that is by design, not a missing feature. A product can come from either the seller (via their LaunchYard dashboard at `launchyard.dev/dashboard`) or the LaunchYard agent that manages this business (it has a built-in tool to create products on the platform Stripe account). Either way, each product ends up with a stable `product_id` that you reference in buy buttons.

So when you've built something sellable but no `product_id` exists yet, do **not** open a support ticket and do **not** block waiting on a human — the product will be created for you. The correct move is:

1. Build the buy button and surrounding flow normally, using a clearly-named placeholder for the id (e.g. `LISTING_DESCRIPTION_PRODUCT_ID = "PENDING"`). Leave a short comment noting the real `product_id` needs to be filled in.
2. State plainly in your final summary that the product still needs to be created and the placeholder swapped for the real `product_id` — that hand-off goes to the managing agent, not to support.

Filing a `contact_support` ticket asking the team to "create a Stripe product" is the wrong escalation: product creation is already supported one layer up, so a human request just stalls the founder on something the platform does automatically.

## Looking Up Documentation

You have access to a real browser via the `browse` CLI. **If you are unsure about any API, syntax, or behavior, look it up instead of guessing.** Wrong guesses waste turns debugging.

Key documentation sites:
- **D1 (database):** `https://developers.cloudflare.com/d1/`
- **R2 (object storage):** `https://developers.cloudflare.com/r2/api/workers/workers-api-reference/`
- **Workers runtime:** `https://developers.cloudflare.com/workers/`
- **Hono framework:** `https://hono.dev/docs/`
- **Workers TypeScript types:** `https://developers.cloudflare.com/workers/languages/typescript/`

To look something up:
```bash
browse open https://developers.cloudflare.com/d1/worker-api/
browse snapshot -c
# read the docs, then close
browse stop
```

Do this whenever you need to use a D1/R2/Hono/Workers API you haven't used before in this session. The cost of a few browse commands is much less than the cost of debugging a wrong guess.

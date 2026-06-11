# New Business

Everything lives inside `worker/`:

```
worker/
  src/
    index.ts         ← All HTML pages and API routes (Hono app)
  site/              ← Static assets only (CSS, images, favicons, robots.txt)
    styles.css       ← Shared styles, served at /styles.css
  launchyard.manifest.json  ← Deployment manifest
```

## Adding pages

HTML pages are Worker routes in `worker/src/index.ts`. Add one with `app.get(...)`:

```ts
app.get("/pricing", (c) => c.html(`<!doctype html>
  <html><head><title>Pricing</title></head>
  <body>...</body></html>`));
```

Clean URLs (`/pricing`, `/about`, dynamic routes like `/p/:slug`) all work the same way.

## site/ is for static assets, not HTML

`worker/site/` is for true static assets — CSS, images, favicons, `robots.txt`. Don't put HTML there. **Precedence trap:** if a file in `site/` exact-matches a request path, the static file wins and the matching Worker route never runs. The home page is a Worker route precisely because mixing static `site/index.html` with a `/` Worker route silently shadows the route.

If you genuinely need a static HTML file (e.g. a vendor verification file), put it under a path you don't also handle as a Worker route. There is no `c.env.ASSETS` binding inside handlers — you cannot read static files from Worker code.

## Adding API routes

Edit `worker/src/index.ts`:

```ts
app.get("/api/products", async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM products").all();
  return c.json(results);
});
```

Call from HTML: `fetch("/api/products").then(r => r.json())`

## Deployment manifest

Edit `worker/launchyard.manifest.json` to configure deployment. The key fields:

- `entrypoint` — your worker entry point (e.g. `"src/index.ts"`)
- `assets_dir` — static assets directory (e.g. `"./site"`)
- `healthcheck_path` — path the platform GETs after deploy to verify the worker is alive (must start with `/`)
- `requested_capabilities` — object declaring what platform resources you need:
  - `"db": "required"` → gives you `c.env.DB` (Cloudflare D1 SQL database)
  - `"object_storage": "required"` → gives you `c.env.FILES_BUCKET` (Cloudflare R2 storage)

Example manifest:
```json
{
  "schema_version": 1,
  "runtime": "cloudflare_worker",
  "entrypoint": "src/index.ts",
  "assets_dir": "./site",
  "healthcheck_path": "/api/healthz",
  "requested_capabilities": {
    "db": "required",
    "object_storage": "required"
  }
}
```

**Important:** `db` and `object_storage` must be nested inside `requested_capabilities`. Do NOT put them as top-level keys.

## Available bindings

These are always available in your worker (no configuration needed):

| Binding | Type | Description |
|---|---|---|
| `COMPANY_ID` | `string` | Your company's unique ID |
| `APP_BASE_URL` | `string` | Your public URL (e.g. `https://myapp.launchyard.app`) |
| `ANALYTICS` | `AnalyticsEngineDataset` | Visitor tracking (used by `/api/_ping`) |

These require `requested_capabilities` in the manifest:

| Binding | Type | Manifest key | Description |
|---|---|---|---|
| `DB` | `D1Database` | `"db": "required"` | Cloudflare D1 SQL database |
| `FILES_BUCKET` | `R2Bucket` | `"object_storage": "required"` | Cloudflare R2 object storage |

## Local development

```bash
cd worker && npm install && npm run dev
```

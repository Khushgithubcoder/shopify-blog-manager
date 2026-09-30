# Shopify Blog Automation

Your original Wix frontend (same UI) + a new **FastAPI backend** that handles Shopify OAuth and publishes to the
client's Shopify blog. The client only clicks **Connect Shopify Store → Authorize/Install → Connected**.
API keys, secrets and tokens live only on the backend (tokens are stored AES/Fernet-encrypted in Postgres).

```
frontend/   HTML/CSS/JS (unchanged design; calls the backend)
backend/    FastAPI: main.py, shopify_api.py, db.py, crypto_utils.py
database/   schema.sql (applied automatically on startup)
```

## 1. Create the Shopify app (once)
In the Shopify Dev Dashboard / Partner Dashboard create an app, then:
- **Scopes:** `read_content, write_content`
- **Allowed redirection URL:** `https://<APP_URL>/shopify/callback`
- Copy the **Client ID** and **Client secret** into `.env` (below).
- Distribution: to install on other merchants' stores use *custom distribution* (install link per store) or the App Store (public).

## 2. Local setup
You need Python 3.11+ and PostgreSQL.
```bash
# database
createdb shopify_blog

# backend
cd backend
python3 -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                   # Windows: copy .env.example .env
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # -> paste as ENCRYPTION_KEY
# edit .env: SHOPIFY_API_KEY, SHOPIFY_API_SECRET, DATABASE_URL, SESSION_SECRET, ENCRYPTION_KEY, APP_URL
```
Shopify must reach your callback over **HTTPS**, so for local testing expose port 8000 with a tunnel and use that URL
as `APP_URL` (and in the app's redirect URL, and set `COOKIE_SECURE=true`):
```bash
cloudflared tunnel --url http://localhost:8000        # or: ngrok http 8000
```
## 3. Run
```bash
cd backend
uvicorn main:app --reload --port 8000
```
Open **`<APP_URL>/login.html`** (use the tunnel URL, so the login cookie and OAuth callback share one domain).
Sign up → **Connect Shopify** → enter `your-store.myshopify.com` → approve on Shopify → you land back as *Connected* →
**Create Post** → **Publish Directly to Shopify**.

The backend serves the `frontend/` folder itself, so there is nothing else to start. (If you host the frontend
elsewhere: set `API_BASE` in `frontend/config.js`, `CORS_ORIGINS` and `FRONTEND_URL` in `.env`.)

## Deploy (Render)
`render.yaml` is included. Set `SHOPIFY_API_KEY`, `SHOPIFY_API_SECRET`, `ENCRYPTION_KEY`, `APP_URL` in the dashboard,
then update the app's redirect URL to `https://<your-render-url>/shopify/callback`.

## API
| Endpoint | Purpose |
|---|---|
| `GET /shopify/connect?shop=` | Starts OAuth (302 to Shopify, random single-use `state`) |
| `GET /shopify/callback` | Verifies HMAC + state, exchanges code (expiring offline token + refresh token), saves encrypted, 302 to `connect-shopify.html` |
| `GET /shopify/status` | `{connected, shop, shopName, storeUrl}` |
| `POST /blogs` · `POST /blogs/{id}/publish` | Create post · publish via Admin GraphQL `articleCreate` |
| `GET/DELETE /blogs`, `POST /blogs/{id}/schedule` | Queue, scheduling (background job, checks every minute) |
| `GET/PATCH/DELETE /shopify/posts[/{id}]`, `POST /shopify/drafts/{id}/publish` | Shopify Blog Manager page |
| `POST /shopify/disconnect`, `/auth/*`, `/sheets/import`, `/audit-logs` | As before |

Interactive docs: `/docs`.

## Things to know
- **Tested** end-to-end against a real Postgres with Shopify mocked (OAuth HMAC/state, token refresh, publish, schedule,
  blog manager, isolation between users). **Not yet run against a live store**, so do one real install test.
  The one call I couldn't confirm from docs is the exact token-endpoint body format; if Shopify rejects the code
  exchange, check `_token_request` in `shopify_api.py`.
- Posts go into the store's **first blog** (a blog called "News" is created if none exists). The store theme controls the look.
- The editor's plain text becomes `<p>` paragraphs; HTML is passed through unchanged.
- Uses Admin API `2026-07` (change with `SHOPIFY_API_VERSION`) and GraphQL only, as Shopify requires for new apps.
- Not built: installs started *from Shopify* (App Store button / admin) - the callback only accepts installs started
  from Connect Shopify; and the mandatory privacy webhooks (`customers/data_request`, `customers/redact`, `shop/redact`)
  plus `app/uninstalled`, which you need before an App Store listing.
- Scheduled times from the picker have no timezone; they're interpreted in the database server's timezone.
- **Rotate any real credentials** that were in the old ZIP's `backend/.env`.

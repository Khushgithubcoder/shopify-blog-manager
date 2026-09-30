"""FastAPI backend for the Shopify blog automation frontend."""
import csv
import io
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from werkzeug.security import check_password_hash, generate_password_hash

import db
import shopify_api as sh
from crypto_utils import decrypt_key, encrypt_key

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
FRONTEND_URL = os.environ.get("FRONTEND_URL", "").rstrip("/")   # '' = same origin


def frontend(path: str) -> str:
    return f"{FRONTEND_URL}/{path}"


# --- App / scheduler ---------------------------------------------------------

def scheduler_loop():
    """Publishes scheduled posts once per minute."""
    while True:
        try:
            for blog in db.get_due_scheduled_blogs():
                if not db.claim_blog(blog["id"]):
                    continue  # another worker took it
                try:
                    res = publish_blog_row(blog)
                    db.record_audit_log(blog["user_id"], "AUTO_PUBLISHED_SCHEDULED",
                                        {"blogId": blog["id"], "shopifyArticleId": res["shopifyArticleId"]})
                except Exception as e:
                    print(f"[Scheduler] {blog['id']} failed: {e}")
                    db.update_blog_status(blog["id"], "failed")
        except Exception as e:
            print(f"[Scheduler] {e}")
        time.sleep(60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        db.init_db()
    except Exception as e:
        print(f"[DB] Could not initialise database: {e}")
    threading.Thread(target=scheduler_loop, daemon=True).start()
    yield


app = FastAPI(title="Shopify Blog Automation", lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET", "dev-secret-change-me"),
    same_site="lax",
    https_only=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
    max_age=60 * 60 * 24 * 14,
)
if os.environ.get("CORS_ORIGINS"):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in os.environ["CORS_ORIGINS"].split(",")],
        allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
    )


# The frontend reads `data.error`, so return errors in that shape.
@app.exception_handler(HTTPException)
async def http_error(_, exc: HTTPException):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def validation_error(_, exc):
    return JSONResponse({"error": "Invalid or missing fields in the request."}, status_code=422)


def current_user_id(request: Request) -> str:
    uid = request.session.get("user_id")
    if not uid:
        raise HTTPException(401, "Please log in first.")
    return uid


# --- Shopify token handling --------------------------------------------------

def get_valid_token(user_id: str):
    """Returns (shop, access_token). Refreshes expiring tokens under a row lock."""
    cred = db.get_credential(user_id)
    if not cred:
        raise HTTPException(400, "No Shopify store connected. Connect one first.")
    exp = cred["access_token_expires_at"]
    if exp is None or exp - datetime.now(timezone.utc) > timedelta(minutes=5):
        return cred["shop"], decrypt_key(cred["encrypted_access_token"])

    with db.tx() as cur:   # lock so two requests never spend the same refresh token
        cur.execute("SELECT * FROM shopify_credentials WHERE user_id = %s FOR UPDATE", (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(400, "No Shopify store connected. Connect one first.")
        exp = row["access_token_expires_at"]
        if exp and exp - datetime.now(timezone.utc) <= timedelta(minutes=5):
            if not row["encrypted_refresh_token"]:
                raise sh.ShopifyAuthError("Shopify access expired. Reconnect the store.")
            t = sh.refresh_tokens(row["shop"], decrypt_key(row["encrypted_refresh_token"]))
            cur.execute(
                """UPDATE shopify_credentials SET encrypted_access_token=%s, encrypted_refresh_token=%s,
                   access_token_expires_at=%s, refresh_token_expires_at=%s, updated_at=CURRENT_TIMESTAMP
                   WHERE user_id=%s""",
                (encrypt_key(t["access_token"]), encrypt_key(t["refresh_token"] or ""),
                 t["access_expires_at"], t["refresh_expires_at"], user_id),
            )
            return row["shop"], t["access_token"]
        return row["shop"], decrypt_key(row["encrypted_access_token"])


def shopify_call(user_id: str, fn, *args, **kwargs):
    """Runs fn(shop, token, ...) and converts Shopify failures into clean API errors."""
    try:
        shop, token = get_valid_token(user_id)
        return fn(shop, token, *args, **kwargs)
    except sh.ShopifyAuthError as e:
        raise HTTPException(400, f"{e} Open Connect Shopify to reconnect.")
    except sh.ShopifyError as e:
        raise HTTPException(502, str(e))


def publish_blog_row(blog: dict) -> dict:
    """Publish a stored blog to the owner's store. Used by the endpoint and the scheduler."""
    uid = blog["user_id"]
    cred = db.get_credential(uid)
    if not cred:
        raise HTTPException(400, "No Shopify store connected. Connect one first.")
    shop, token = get_valid_token(uid)
    article = sh.create_article(shop, token, cred["store_url"], blog["title"], blog["content"],
                                blog["image_url"], author=cred["shop_name"], publish=True)
    db.update_blog_status(blog["id"], "published", shopify_article_id=article["id"])
    return {"shopifyArticleId": article["id"], "url": article["url"]}


# --- Auth --------------------------------------------------------------------

class AuthIn(BaseModel):
    email: str
    password: str


@app.post("/auth/signup")
def signup(body: AuthIn, request: Request):
    email = body.email.strip().lower()
    if not email or not body.password:
        raise HTTPException(400, "Email and password are required.")
    try:
        uid = db.create_user(email, generate_password_hash(body.password))
    except ValueError:
        raise HTTPException(409, "An account with that email already exists.")
    request.session["user_id"] = uid
    return {"success": True, "userId": uid, "email": email}


@app.post("/auth/login")
def login(body: AuthIn, request: Request):
    user = db.find_user_by_email(body.email.strip().lower())
    if not user or not check_password_hash(user["password_hash"], body.password):
        raise HTTPException(401, "Invalid email or password.")
    request.session["user_id"] = user["id"]
    return {"success": True, "userId": user["id"], "email": user["email"]}


@app.post("/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"success": True}


@app.get("/auth/me")
def me(uid: str = Depends(current_user_id)):
    user = db.find_user_by_id(uid)
    if not user:
        raise HTTPException(401, "Not logged in.")
    return {"userId": user["id"], "email": user["email"]}


# --- Shopify OAuth -----------------------------------------------------------

@app.get("/shopify/connect")
def shopify_connect(request: Request, shop: str = ""):
    """Browser navigation. Starts Shopify OAuth by redirecting to Shopify's authorize page."""
    uid = request.session.get("user_id")
    if not uid:
        return RedirectResponse(frontend("login.html"))
    shop = shop.strip().lower()
    if not sh.is_valid_shop(shop):
        return RedirectResponse(frontend("connect-shopify.html?error=" + quote("Enter a valid store address like your-store.myshopify.com")))
    try:
        state = secrets.token_urlsafe(32)
        db.create_oauth_state(state, uid, shop)
        return RedirectResponse(sh.install_url(shop, state))
    except sh.ShopifyError as e:
        return RedirectResponse(frontend("connect-shopify.html?error=" + quote(str(e))))


@app.get("/shopify/callback")
def shopify_callback(request: Request):
    """Shopify redirects here after the merchant approves. We verify, swap the code for tokens, save."""
    def fail(msg):
        return RedirectResponse(frontend("connect-shopify.html?error=" + quote(msg)))

    params = dict(request.query_params)
    shop, code, state = params.get("shop", ""), params.get("code", ""), params.get("state", "")
    if params.get("error"):
        return fail("Shopify authorization was cancelled or denied.")
    try:
        if not (sh.is_valid_shop(shop) and code and state and params.get("hmac")):
            return fail("Invalid response from Shopify.")
        if not sh.verify_callback_hmac(params):
            return fail("Could not verify the response came from Shopify.")
        st = db.consume_oauth_state(state)
        if not st or not st["fresh"] or st["shop"] != shop:
            return fail("This connection attempt expired. Please try again.")

        t = sh.exchange_code(shop, code)
        info = sh.get_shop_info(shop, t["access_token"])
        db.save_credential(
            st["user_id"], shop, info["name"], info["url"], t["scope"],
            encrypt_key(t["access_token"]), encrypt_key(t["refresh_token"] or "") or None,
            t["access_expires_at"], t["refresh_expires_at"],
        )
        db.record_audit_log(st["user_id"], "SHOPIFY_CONNECTED", {"shop": shop})
        return RedirectResponse(frontend("connect-shopify.html"))
    except sh.ShopifyError as e:
        return fail(str(e))
    except Exception as e:
        print(f"[OAuth callback] {e}")
        return fail("Something went wrong connecting your store. Please try again.")


@app.get("/shopify/status")
def shopify_status(uid: str = Depends(current_user_id)):
    cred = db.get_credential(uid)
    if not cred:
        return {"connected": False}
    return {"connected": True, "shop": cred["shop"], "shopName": cred["shop_name"], "storeUrl": cred["store_url"]}


@app.post("/shopify/disconnect")
def shopify_disconnect(uid: str = Depends(current_user_id)):
    db.delete_credential(uid)
    db.record_audit_log(uid, "SHOPIFY_DISCONNECTED")
    return {"success": True}


# --- Live Shopify posts (Blog Manager) ---------------------------------------

class PostIn(BaseModel):
    title: str
    content: str
    imageUrl: Optional[str] = None


def _cred(uid):
    return db.get_credential(uid) or {}


@app.get("/shopify/posts")
def list_posts(uid: str = Depends(current_user_id)):
    return shopify_call(uid, lambda shop, tok: sh.list_articles(shop, tok, _cred(uid).get("store_url")))


@app.get("/shopify/posts/{post_id}")
def get_post(post_id: str, isDraft: bool = False, uid: str = Depends(current_user_id)):
    return shopify_call(uid, sh.get_article, post_id)


@app.patch("/shopify/posts/{post_id}")
def update_post(post_id: str, body: PostIn, isDraft: bool = False, uid: str = Depends(current_user_id)):
    shopify_call(uid, sh.update_article, post_id, body.title, body.content, body.imageUrl)
    db.record_audit_log(uid, "UPDATED_SHOPIFY_POST", {"articleId": post_id})
    return {"success": True}


@app.post("/shopify/drafts/{post_id}/publish")
def publish_draft(post_id: str, uid: str = Depends(current_user_id)):
    shopify_call(uid, sh.update_article, post_id, publish=True)
    db.record_audit_log(uid, "PUBLISHED_SHOPIFY_DRAFT", {"articleId": post_id})
    return {"success": True}


@app.delete("/shopify/posts/{post_id}")
def delete_post(post_id: str, isDraft: bool = False, uid: str = Depends(current_user_id)):
    shopify_call(uid, sh.delete_article, post_id)
    db.record_audit_log(uid, "DELETED_SHOPIFY_POST", {"articleId": post_id})
    return {"success": True}


# --- Blogs: local drafts, publish, schedule ----------------------------------

class ScheduleIn(BaseModel):
    scheduledFor: str


def _own_blog(blog_id: str, uid: str) -> dict:
    blog = db.get_blog(blog_id)
    if not blog or blog["user_id"] != uid:
        raise HTTPException(404, "Blog not found.")
    return blog


@app.post("/blogs")
def create_blog(body: PostIn, uid: str = Depends(current_user_id)):
    if not body.title.strip() or not body.content.strip():
        raise HTTPException(400, "Title and content are required.")
    return db.save_blog(uid, body.title.strip(), body.content.strip(), (body.imageUrl or "").strip() or None)


@app.get("/blogs")
def list_blogs(uid: str = Depends(current_user_id)):
    return db.get_blogs_for_user(uid)


@app.post("/blogs/{blog_id}/publish")
def publish_blog(blog_id: str, uid: str = Depends(current_user_id)):
    blog = _own_blog(blog_id, uid)
    try:
        res = publish_blog_row(blog)
    except HTTPException:
        raise   # e.g. not connected: keep as-is, don't mark the post failed
    except sh.ShopifyAuthError as e:
        raise HTTPException(400, f"Publishing failed: {e} Open Connect Shopify to reconnect.")
    except Exception as e:
        db.update_blog_status(blog_id, "failed")
        return JSONResponse({"error": "Publishing to Shopify failed.", "details": str(e)}, status_code=502)
    db.record_audit_log(uid, "PUBLISHED_BLOG", {"blogId": blog_id, **res})
    return {"success": True, "id": blog_id, "status": "published", **res}


@app.post("/blogs/{blog_id}/schedule")
def schedule_blog(blog_id: str, body: ScheduleIn, uid: str = Depends(current_user_id)):
    _own_blog(blog_id, uid)
    db.update_blog_status(blog_id, "scheduled", scheduled_for=body.scheduledFor)
    db.record_audit_log(uid, "SCHEDULED_BLOG", {"blogId": blog_id, "scheduledFor": body.scheduledFor})
    return db.get_blog(blog_id)


@app.delete("/blogs/{blog_id}")
def delete_blog(blog_id: str, uid: str = Depends(current_user_id)):
    _own_blog(blog_id, uid)
    db.delete_blog(blog_id)
    return {"success": True}


# --- Google Sheets import / audit log ----------------------------------------

class SheetIn(BaseModel):
    csvUrl: str


ALLOWED_SHEET_HOSTS = ("docs.google.com", "googleusercontent.com")


@app.post("/sheets/import")
def import_sheet(body: SheetIn, uid: str = Depends(current_user_id)):
    u = urlparse(body.csvUrl.strip())
    host = u.hostname or ""
    if u.scheme != "https" or not any(host == h or host.endswith("." + h) for h in ALLOWED_SHEET_HOSTS):
        raise HTTPException(400, "Use the published Google Sheets CSV link (https://docs.google.com/...).")
    try:
        resp = requests.get(body.csvUrl.strip(), timeout=15)
        resp.raise_for_status()
        imported = 0
        for row in csv.DictReader(io.StringIO(resp.text)):
            title = (row.get("title") or row.get("Title") or "").strip()
            content = (row.get("content") or row.get("Content") or "").strip()
            image = (row.get("image") or row.get("image_url") or row.get("Image") or "").strip() or None
            if title and content:
                db.save_blog(uid, title, content, image)
                imported += 1
    except Exception as e:
        raise HTTPException(500, f"Could not read sheet. Ensure it is published as CSV ({e})")
    db.record_audit_log(uid, "IMPORTED_SHEETS", {"importedCount": imported})
    return {"imported": imported}


@app.get("/audit-logs")
def audit_logs(uid: str = Depends(current_user_id)):
    return db.get_audit_logs(uid)


# --- Frontend (same-origin serving) ------------------------------------------

@app.get("/")
def root():
    return RedirectResponse("/login.html")


if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

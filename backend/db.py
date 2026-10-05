"""PostgreSQL access layer (psycopg2). Same tables/behaviour as the Wix version, minus Wix."""
import json
import os
import uuid
from contextlib import contextmanager
from pathlib import Path

import psycopg2
from psycopg2.extras import RealDictCursor

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "database" / "schema.sql"


def _connect():
    url = os.environ.get("DATABASE_URL")
    if url:
        return psycopg2.connect(url, cursor_factory=RealDictCursor)
    return psycopg2.connect(
        host=os.environ.get("PGHOST", "localhost"),
        port=int(os.environ.get("PGPORT", 5432)),
        user=os.environ.get("PGUSER", "postgres"),
        password=os.environ.get("PGPASSWORD", ""),
        dbname=os.environ.get("PGDATABASE", "shopify_blog"),
        cursor_factory=RealDictCursor,
    )


@contextmanager
def tx():
    """One transaction. Commits on success, rolls back on error."""
    conn = _connect()
    try:
        with conn.cursor() as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _one(sql, params=()):
    with tx() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None


def _all(sql, params=()):
    with tx() as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


def _run(sql, params=()):
    with tx() as cur:
        cur.execute(sql, params)
        return cur.rowcount


def init_db():
    with tx() as cur:
        cur.execute(SCHEMA_PATH.read_text(encoding="utf-8"))


# --- Users -------------------------------------------------------------------

def create_user(email, password_hash):
    user_id = f"u_{uuid.uuid4().hex[:12]}"
    try:
        _run("INSERT INTO users (id, email, password_hash) VALUES (%s, %s, %s)", (user_id, email, password_hash))
    except psycopg2.IntegrityError:
        raise ValueError("EMAIL_TAKEN")
    return user_id


def find_user_by_email(email):
    return _one("SELECT * FROM users WHERE email = %s", (email,))


def find_user_by_id(user_id):
    return _one("SELECT * FROM users WHERE id = %s", (user_id,))


# --- Shopify connection ------------------------------------------------------

def save_credential(user_id, shop, shop_name, store_url, scopes, enc_access, enc_refresh, access_exp, refresh_exp):
    _run(
        """
        INSERT INTO shopify_credentials
          (user_id, shop, shop_name, store_url, scopes, encrypted_access_token,
           encrypted_refresh_token, access_token_expires_at, refresh_token_expires_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (user_id) DO UPDATE SET
          shop = EXCLUDED.shop, shop_name = EXCLUDED.shop_name, store_url = EXCLUDED.store_url,
          scopes = EXCLUDED.scopes, encrypted_access_token = EXCLUDED.encrypted_access_token,
          encrypted_refresh_token = EXCLUDED.encrypted_refresh_token,
          access_token_expires_at = EXCLUDED.access_token_expires_at,
          refresh_token_expires_at = EXCLUDED.refresh_token_expires_at,
          connected_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
        """,
        (user_id, shop, shop_name, store_url, scopes, enc_access, enc_refresh, access_exp, refresh_exp),
    )


def get_credential(user_id):
    return _one("SELECT * FROM shopify_credentials WHERE user_id = %s", (user_id,))


def delete_credential(user_id):
    _run("DELETE FROM shopify_credentials WHERE user_id = %s", (user_id,))


def create_oauth_state(state, user_id, shop):
    _run("DELETE FROM oauth_states WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '1 hour'")
    _run("INSERT INTO oauth_states (state, user_id, shop) VALUES (%s,%s,%s)", (state, user_id, shop))


def consume_oauth_state(state):
    """Returns the state row if it exists and is <10 min old, and deletes it (single use)."""
    return _one(
        """
        DELETE FROM oauth_states
        WHERE state = %s
        RETURNING user_id, shop, (created_at > CURRENT_TIMESTAMP - INTERVAL '10 minutes') AS fresh
        """,
        (state,),
    )


# --- Blogs -------------------------------------------------------------------

def save_blog(user_id, title, content, image_url=None, status="draft"):
    return _one(
        """
        INSERT INTO blogs (id, user_id, title, content, image_url, status)
        VALUES (%s,%s,%s,%s,%s,%s) RETURNING *
        """,
        (f"b_{uuid.uuid4().hex[:12]}", user_id, title, content, image_url, status),
    )


def get_blog(blog_id):
    return _one("SELECT * FROM blogs WHERE id = %s", (blog_id,))


def get_blogs_for_user(user_id):
    return _all("SELECT * FROM blogs WHERE user_id = %s ORDER BY created_at DESC", (user_id,))


def update_blog_status(blog_id, status, shopify_article_id=None, scheduled_for=None, clear_scheduled=False):
    if scheduled_for is None and not clear_scheduled:
        scheduled_for_sql = "scheduled_for = scheduled_for"
        params = (status, shopify_article_id, blog_id)
    elif clear_scheduled:
        scheduled_for_sql = "scheduled_for = NULL"
        params = (status, shopify_article_id, blog_id)
    else:
        scheduled_for_sql = "scheduled_for = %s"
        params = (status, shopify_article_id, scheduled_for, blog_id)

    _run(
        f"""
        UPDATE blogs SET status = %s,
          shopify_article_id = COALESCE(%s, shopify_article_id),
          {scheduled_for_sql},
          updated_at = CURRENT_TIMESTAMP
        WHERE id = %s
        """,
        params,
    )


def delete_blog(blog_id):
    _run("DELETE FROM blogs WHERE id = %s", (blog_id,))


def get_due_scheduled_blogs():
    return _all("SELECT * FROM blogs WHERE status = 'scheduled' AND scheduled_for <= CURRENT_TIMESTAMP ORDER BY scheduled_for ASC")


def claim_blog(blog_id):
    """Atomically move scheduled -> publishing so multiple workers never double-publish."""
    return _run("UPDATE blogs SET status = 'publishing' WHERE id = %s AND status = 'scheduled'", (blog_id,)) == 1


# --- Audit logs --------------------------------------------------------------

def record_audit_log(user_id, action, details=None):
    try:
        _run(
            "INSERT INTO audit_logs (user_id, action, details) VALUES (%s,%s,%s::jsonb)",
            (user_id, action, json.dumps(details or {})),
        )
    except Exception as e:  # never let logging break a request
        print(f"[AuditLog] {e}")


def get_audit_logs(user_id, limit=50):
    return _all("SELECT * FROM audit_logs WHERE user_id = %s ORDER BY created_at DESC LIMIT %s", (user_id, limit))

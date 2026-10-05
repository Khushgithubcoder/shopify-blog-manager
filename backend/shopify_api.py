"""Shopify OAuth + Admin GraphQL helpers. Secrets come from env vars and never leave the backend."""
import hashlib
import hmac
import os
import re
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from urllib.parse import urlencode, urlparse

import requests

SHOP_RE = re.compile(r"^[a-z0-9][a-z0-9-]*\.myshopify\.com$")
TIMEOUT = 30


class ShopifyError(Exception):
    pass


class ShopifyAuthError(ShopifyError):
    """Token missing/expired/revoked -> the merchant must reconnect."""


def _env(name, default=None):
    v = os.environ.get(name, default)
    if v is None or v == "":
        raise ShopifyError(f"Server is missing the {name} setting.")
    return v


def api_version():
    return os.environ.get("SHOPIFY_API_VERSION", "2026-07")


def is_valid_shop(shop: str) -> bool:
    return bool(shop and SHOP_RE.match(shop))


# --- OAuth -------------------------------------------------------------------

def redirect_uri():
    return _env("APP_URL").rstrip("/") + "/shopify/callback"


def install_url(shop: str, state: str) -> str:
    qs = urlencode({
        "client_id": _env("SHOPIFY_API_KEY"),
        "scope": os.environ.get("SHOPIFY_SCOPES", "read_content,write_content"),
        "redirect_uri": redirect_uri(),
        "state": state,
    })
    return f"https://{shop}/admin/oauth/authorize?{qs}"


def verify_callback_hmac(params: dict) -> bool:
    """Shopify signs the callback query string with the app secret (HMAC-SHA256, hex)."""
    received = params.get("hmac", "")
    message = "&".join(f"{k}={v}" for k, v in sorted(params.items()) if k != "hmac")
    digest = hmac.new(_env("SHOPIFY_API_SECRET").encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, received)


def _token_fields(data: dict) -> dict:
    now = datetime.now(timezone.utc)
    if not data.get("access_token"):
        raise ShopifyError("Shopify did not return an access token.")
    exp = data.get("expires_in")
    rexp = data.get("refresh_token_expires_in")
    return {
        "access_token": data["access_token"],
        "refresh_token": data.get("refresh_token"),
        "access_expires_at": now + timedelta(seconds=int(exp)) if exp else None,
        "refresh_expires_at": now + timedelta(seconds=int(rexp)) if rexp else None,
        "scope": data.get("scope", ""),
    }


def _token_request(shop: str, payload: dict) -> dict:
    r = requests.post(f"https://{shop}/admin/oauth/access_token", json=payload, timeout=TIMEOUT)
    if r.status_code in (400, 401, 403):
        raise ShopifyAuthError(f"Shopify rejected the authorization ({r.status_code}).")
    if not r.ok:
        raise ShopifyError(f"Shopify token endpoint error ({r.status_code}).")
    return _token_fields(r.json())


def exchange_code(shop: str, code: str) -> dict:
    # expiring=1 -> 60-min access token + refresh token (required for new public apps)
    return _token_request(shop, {
        "client_id": _env("SHOPIFY_API_KEY"),
        "client_secret": _env("SHOPIFY_API_SECRET"),
        "code": code,
        "expiring": 1,
    })


def refresh_tokens(shop: str, refresh_token: str) -> dict:
    return _token_request(shop, {
        "client_id": _env("SHOPIFY_API_KEY"),
        "client_secret": _env("SHOPIFY_API_SECRET"),
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    })


# --- GraphQL -----------------------------------------------------------------

def gql(shop: str, token: str, query: str, variables: dict | None = None) -> dict:
    r = requests.post(
        f"https://{shop}/admin/api/{api_version()}/graphql.json",
        json={"query": query, "variables": variables or {}},
        headers={"X-Shopify-Access-Token": token, "Content-Type": "application/json"},
        timeout=TIMEOUT,
    )
    if r.status_code in (401, 403):
        raise ShopifyAuthError("Shopify rejected the access token. Reconnect the store.")
    if r.status_code == 429:
        raise ShopifyError("Shopify is rate-limiting requests. Try again in a moment.")
    if not r.ok:
        raise ShopifyError(f"Shopify API error ({r.status_code}).")
    body = r.json()
    if body.get("errors"):
        msgs = "; ".join(e.get("message", "error") for e in body["errors"])
        raise ShopifyError(msgs)
    return body["data"]


def _user_errors(errors):
    if errors:
        raise ShopifyError("; ".join(f"{'.'.join(e.get('field') or [])}: {e['message']}".strip(": ") for e in errors))


def get_shop_info(shop: str, token: str) -> dict:
    d = gql(shop, token, "{ shop { name url } }")["shop"]
    return {"name": d["name"], "url": d["url"]}


def num_id(gid: str) -> str:
    return gid.rsplit("/", 1)[-1]


def article_gid(numeric_id: str) -> str:
    if not str(numeric_id).isdigit():
        raise ShopifyError("Invalid article id.")
    return f"gid://shopify/Article/{numeric_id}"


SAFE_HTML_TAGS = {
    "p", "br", "strong", "b", "em", "i", "u", "s", "ul", "ol", "li",
    "blockquote", "h1", "h2", "h3", "h4", "h5", "h6", "a", "img",
    "div", "span", "table", "thead", "tbody", "tr", "td", "th", "code",
    "pre", "hr"
}
FORBIDDEN_HTML_TAGS = {"script", "style", "iframe", "object", "embed", "svg", "math", "link", "meta", "base"}


class _SafeHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.parts = []
        self._blocked_depth = 0

    def _safe_attrs(self, tag: str, attrs):
        result = []
        for name, value in attrs or []:
            if not name:
                continue
            attr = name.lower()
            if attr.startswith("on"):
                continue
            if tag == "a" and attr in {"href", "title", "target", "rel"}:
                if attr == "href":
                    href = (value or "").strip()
                    if not href:
                        continue
                    parsed = urlparse(href)
                    if parsed.scheme and parsed.scheme.lower() not in {"http", "https", "mailto"}:
                        continue
                    result.append((name, href))
                    continue
                if value is not None:
                    result.append((name, value))
            elif tag == "img" and attr in {"src", "alt", "title"}:
                if attr == "src":
                    src = (value or "").strip()
                    if not src:
                        continue
                    parsed = urlparse(src)
                    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
                        continue
                    result.append((name, src))
                    continue
                if value is not None:
                    result.append((name, value))
        return result

    def _emit_attrs(self, attrs):
        if not attrs:
            return ""
        chunks = []
        for name, value in attrs:
            escaped = value.replace('"', '&quot;') if value is not None else ""
            chunks.append(f' {name}="{escaped}"')
        return "".join(chunks)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in FORBIDDEN_HTML_TAGS:
            self._blocked_depth += 1
            return
        if self._blocked_depth > 0 or tag not in SAFE_HTML_TAGS:
            return
        safe_attrs = self._safe_attrs(tag, attrs)
        self.parts.append(f"<{tag}{self._emit_attrs(safe_attrs)}>")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self._blocked_depth > 0:
            if tag in FORBIDDEN_HTML_TAGS:
                self._blocked_depth = max(0, self._blocked_depth - 1)
            return
        if tag in SAFE_HTML_TAGS:
            self.parts.append(f"</{tag}>")

    def handle_data(self, data):
        if data and self._blocked_depth == 0:
            self.parts.append(data)

    def handle_entityref(self, name):
        self.parts.append(f"&{name};")

    def handle_charref(self, name):
        self.parts.append(f"&#{name};")


def sanitize_html(content: str) -> str:
    """Allow a small, safe subset of rich text and strip script/event-handler payloads."""
    if not content:
        return ""
    parser = _SafeHTMLParser()
    parser.feed(content)
    parser.close()
    return "".join(parser.parts)


def text_to_html(content: str) -> str:
    """Convert plain text to safe HTML and preserve a known-good rich-text subset."""
    clean = sanitize_html(content or "")
    if re.search(r"</?(p|h[1-6]|ul|ol|li|div|br|img|a|blockquote|strong|em|table|thead|tbody|tr|td|th|code|pre)\b", clean, re.I):
        return clean
    from html import escape
    paras = [p.strip() for p in re.split(r"\n\s*\n", clean.strip()) if p.strip()]
    return "".join(f"<p>{escape(p).replace(chr(10), '<br>')}</p>" for p in paras)


def _default_blog_id(shop: str, token: str) -> str:
    """Publish into the store's first blog; create one called 'News' if the store has none."""
    nodes = gql(shop, token, "{ blogs(first: 1) { nodes { id } } }")["blogs"]["nodes"]
    if nodes:
        return nodes[0]["id"]
    p = gql(shop, token,
            "mutation($blog: BlogCreateInput!){ blogCreate(blog:$blog){ blog{ id } userErrors{ field message } } }",
            {"blog": {"title": "News"}})["blogCreate"]
    _user_errors(p["userErrors"])
    return p["blog"]["id"]


_ARTICLE_FIELDS = "id title handle isPublished publishedAt updatedAt blog { handle }"


def _article_url(store_url: str, a: dict) -> str | None:
    if not a.get("isPublished") or not store_url:
        return None
    return f"{store_url.rstrip('/')}/blogs/{a['blog']['handle']}/{a['handle']}"


def _image(url, alt):
    return {"url": url, "altText": alt} if url and url.lower().startswith(("http://", "https://")) else None


def create_article(shop, token, store_url, title, content, image_url, author, publish=True) -> dict:
    article = {
        "blogId": _default_blog_id(shop, token),
        "title": title,
        "author": {"name": author or "Editor"},   # author is required by Shopify
        "body": text_to_html(content),
        "isPublished": publish,
    }
    img = _image(image_url, title)
    if img:
        article["image"] = img
    p = gql(shop, token,
            f"mutation($article: ArticleCreateInput!){{ articleCreate(article:$article){{ article {{ {_ARTICLE_FIELDS} }} userErrors{{ field message }} }} }}",
            {"article": article})["articleCreate"]
    _user_errors(p["userErrors"])
    a = p["article"]
    return {"id": num_id(a["id"]), "url": _article_url(store_url, a)}


def list_articles(shop, token, store_url) -> dict:
    nodes = gql(shop, token, f"query($n:Int!){{ articles(first:$n){{ nodes {{ {_ARTICLE_FIELDS} }} }} }}", {"n": 100})["articles"]["nodes"]
    nodes.sort(key=lambda a: a.get("updatedAt") or "", reverse=True)
    items = [{
        "id": num_id(a["id"]), "title": a["title"], "url": _article_url(store_url, a),
        "publishedDate": a.get("publishedAt"), "lastModified": a.get("updatedAt"), "isPublished": a["isPublished"],
    } for a in nodes]
    pub = [i for i in items if i["isPublished"]]
    drafts = [i for i in items if not i["isPublished"]]
    return {"published": pub, "drafts": drafts, "totalPublished": len(pub), "totalDrafts": len(drafts)}


def get_article(shop, token, numeric_id) -> dict:
    a = gql(shop, token, "query($id:ID!){ article(id:$id){ id title body isPublished image { url } } }",
            {"id": article_gid(numeric_id)})["article"]
    if not a:
        raise ShopifyError("Article not found.")
    return {"id": num_id(a["id"]), "title": a["title"], "body_html": a["body"] or "",
            "imageUrl": (a.get("image") or {}).get("url"), "isPublished": a["isPublished"]}


def update_article(shop, token, numeric_id, title=None, content=None, image_url=None, publish=None):
    article = {}
    if title is not None:
        article["title"] = title
    if content is not None:
        article["body"] = text_to_html(content)
    if publish is not None:
        article["isPublished"] = publish
    img = _image(image_url, title)
    if img:
        article["image"] = img
    p = gql(shop, token,
            "mutation($id:ID!,$article:ArticleUpdateInput!){ articleUpdate(id:$id, article:$article){ article{ id } userErrors{ field message } } }",
            {"id": article_gid(numeric_id), "article": article})["articleUpdate"]
    _user_errors(p["userErrors"])


def delete_article(shop, token, numeric_id):
    p = gql(shop, token, "mutation($id:ID!){ articleDelete(id:$id){ deletedArticleId userErrors{ field message } } }",
            {"id": article_gid(numeric_id)})["articleDelete"]
    _user_errors(p["userErrors"])

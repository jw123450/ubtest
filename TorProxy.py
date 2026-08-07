#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote_plus, unquote, urljoin, urlparse, parse_qs
import urllib.request
import urllib.error
import http.cookiejar
import ssl
import gzip
import zlib
import json
import re
import base64
import threading
import secrets

import socks #backend on Socks5 @ localhost:9050 or 127.0.0.1:9050
import socket
import requests


try:
    import brotli  # type: ignore
except ImportError:
    brotli = None

proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}
socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050, rdns=True)
socket.socket = socks.socksocket

PORT = 8888
DUCKDUCKGO_SEARCH = "https://duckduckgo.com/?q={query}"
REMOTE_TIMEOUT_SECONDS = 35
SESSION_COOKIE_NAME = "proxy_session"

COOKIE_JAR = http.cookiejar.CookieJar()
COOKIE_PROCESSOR = urllib.request.HTTPCookieProcessor(COOKIE_JAR)

SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE
#ssl._create_default_https_context = ssl._create_unverified_context #test

HTTPS_HANDLER = urllib.request.HTTPSHandler(context=SSL_CONTEXT)
OPENER = urllib.request.build_opener(COOKIE_PROCESSOR, HTTPS_HANDLER)
SESSION_LAST_BASE = {}
SESSION_LOCK = threading.Lock()


def encode_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def decode_url(encoded: str) -> str:
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    return base64.urlsafe_b64decode((encoded + padding).encode("ascii")).decode("utf-8")


def looks_like_url(value: str) -> bool:
    lowered = value.lower()
    if lowered.startswith(("http://", "https://")):
        return True
    if " " in value:
        return False
    # if lowered.startswith("localhost"):
    #     return False #True
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?(/.*)?$", value):
        return True
    if "." in value:
        return True
    return False


def normalize_destination(user_input: str) -> str:
    raw = user_input.strip()
    if not raw:
        return DUCKDUCKGO_SEARCH.format(query="")
    if looks_like_url(raw):
        if raw.startswith("//"):
            return "https:" + raw
        if not raw.lower().startswith(("http://", "https://")):
            return "https://" + raw
        return raw
    return DUCKDUCKGO_SEARCH.format(query=quote_plus(raw))


def safe_join_query(url: str, query_string: str) -> str:
    if not query_string:
        return url
    if "?" in url:
        return f"{url}&{query_string}"
    return f"{url}?{query_string}"


def should_not_proxy(candidate: str) -> bool:
    if not candidate:
        return True
    lowered = candidate.lower()
    return lowered.startswith(
        ("#", "data:", "javascript:", "mailto:", "tel:", "about:", "blob:")
    )


def to_proxy_url(base_url: str, candidate: str) -> str:
    value = candidate.strip()
    if should_not_proxy(value):
        return value
    if value.startswith("/proxy/"):
        return value
    if value.startswith("//"):
        absolute = urlparse(base_url).scheme + ":" + value
    elif value.startswith(("http://", "https://")):
        absolute = value
    else:
        absolute = urljoin(base_url, value)
    return "/proxy/" + encode_url(absolute)


def rewrite_css(css_text: str, base_url: str) -> str:
    def repl_url(match):
        inner = match.group(1).strip().strip("\"'")
        if should_not_proxy(inner):
            return match.group(0)
        return f"url('{to_proxy_url(base_url, inner)}')"

    def repl_import(match):
        import_target = match.group(1).strip().strip("\"'")
        if should_not_proxy(import_target):
            return match.group(0)
        return f"@import url('{to_proxy_url(base_url, import_target)}')"

    rewritten = re.sub(r"url\(([^)]+)\)", repl_url, css_text, flags=re.IGNORECASE)
    rewritten = re.sub(
        r"@import\s+(?:url\()?['\"]?([^'\"\)]+)['\"]?\)?",
        repl_import,
        rewritten,
        flags=re.IGNORECASE,
    )
    return rewritten


def rewrite_html(html_text: str, base_url: str) -> str:
    def rewrite_attr(match):
        attr = match.group(1)
        quote = match.group(2)
        original = match.group(3)
        return f"{attr}={quote}{to_proxy_url(base_url, original)}{quote}"

    def rewrite_srcset(match):
        quote = match.group(1)
        srcset_value = match.group(2)
        output_parts = []
        for part in srcset_value.split(","):
            item = part.strip()
            if not item:
                continue
            if " " in item:
                url, descriptor = item.rsplit(" ", 1)
                output_parts.append(f"{to_proxy_url(base_url, url.strip())} {descriptor}")
            else:
                output_parts.append(to_proxy_url(base_url, item))
        return f"srcset={quote}{', '.join(output_parts)}{quote}"

    def rewrite_inline_style(match):
        style_value = match.group(1)

        def style_url_repl(style_match):
            style_url = style_match.group(1).strip().strip("\"'")
            if should_not_proxy(style_url):
                return style_match.group(0)
            return f"url('{to_proxy_url(base_url, style_url)}')"

        rewritten_style = re.sub(
            r"url\(([^)]+)\)", style_url_repl, style_value, flags=re.IGNORECASE
        )
        return f'style="{rewritten_style}"'

    rewritten = re.sub(
        r"(src|href|action|poster|data-src)=([\"'])([^\"']*)\2",
        rewrite_attr,
        html_text,
        flags=re.IGNORECASE,
    )
    rewritten = re.sub(
        r"srcset=([\"'])([^\"']*)\1", rewrite_srcset, rewritten, flags=re.IGNORECASE
    )
    rewritten = re.sub(
        r'style="([^"]*)"', rewrite_inline_style, rewritten, flags=re.IGNORECASE
    )
    rewritten = re.sub(
        r"<base[^>]*>",
        "",
        rewritten,
        flags=re.IGNORECASE,
    )
    rewritten = re.sub(
        r'(<meta[^>]+http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=)([^"\']+)(["\'])',
        lambda m: m.group(1) + to_proxy_url(base_url, m.group(2)) + m.group(3),
        rewritten,
        flags=re.IGNORECASE,
    )

    injection = f"""
<script>
(function() {{
  const BASE_URL = {json.dumps(base_url)};
  const toProxy = (raw) => {{
    if (!raw) return raw;
    const val = String(raw).trim();
    const lower = val.toLowerCase();
    if (
      lower.startsWith('#') ||
      lower.startsWith('data:') ||
      lower.startsWith('javascript:') ||
      lower.startsWith('mailto:') ||
      lower.startsWith('tel:') ||
      lower.startsWith('blob:')
    ) {{
      return val;
    }}
    if (val.startsWith('/proxy/')) return val;
    let absolute = val;
    if (val.startsWith('//')) absolute = window.location.protocol + val;
    else if (!/^https?:\\/\\//i.test(val)) absolute = new URL(val, BASE_URL).toString();
    const encoded = btoa(absolute).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, '');
    return '/proxy/' + encoded;
  }};

  const originalFetch = window.fetch;
  window.fetch = function(input, init) {{
    try {{
      if (typeof input === 'string') {{
        return originalFetch.call(this, toProxy(input), init);
      }}
      if (input instanceof Request) {{
        const proxiedRequest = new Request(toProxy(input.url), input);
        return originalFetch.call(this, proxiedRequest, init);
      }}
      if (input && input.url) {{
        return originalFetch.call(this, toProxy(input.url), init);
      }}
    }} catch (_) {{}}
    return originalFetch.call(this, input, init);
  }};

  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {{
    const nextUrl = typeof url === 'string' ? toProxy(url) : url;
    return originalOpen.call(this, method, nextUrl, ...Array.prototype.slice.call(arguments, 2));
  }};

  const originalSendBeacon = navigator.sendBeacon ? navigator.sendBeacon.bind(navigator) : null;
  if (originalSendBeacon) {{
    navigator.sendBeacon = function(url, data) {{
      return originalSendBeacon(toProxy(url), data);
    }};
  }}

  const originalAssign = window.location.assign.bind(window.location);
  const originalReplace = window.location.replace.bind(window.location);
  window.location.assign = function(url) {{ return originalAssign(toProxy(url)); }};
  window.location.replace = function(url) {{ return originalReplace(toProxy(url)); }};
  const originalPushState = history.pushState.bind(history);
  const originalReplaceState = history.replaceState.bind(history);
  history.pushState = function(state, title, url) {{
    if (typeof url === 'string' && url) return originalPushState(state, title, toProxy(url));
    return originalPushState(state, title, url);
  }};
  history.replaceState = function(state, title, url) {{
    if (typeof url === 'string' && url) return originalReplaceState(state, title, toProxy(url));
    return originalReplaceState(state, title, url);
  }};
  const originalOpen = window.open ? window.open.bind(window) : null;
  if (originalOpen) {{
    window.open = function(url, target, features) {{
      if (typeof url === 'string' && url) return originalOpen(toProxy(url), target, features);
      return originalOpen(url, target, features);
    }};
  }}

  document.addEventListener('click', function(e) {{
    const a = e.target.closest('a');
    if (!a) return;
    const href = a.getAttribute('href');
    if (!href) return;
    const proxied = toProxy(href);
    if (proxied === href) return;
    e.preventDefault();
    window.location.href = proxied;
  }}, true);

  document.addEventListener('submit', function(e) {{
    const form = e.target;
    if (!form) return;
    const action = form.getAttribute('action') || form.action || BASE_URL;
    const proxiedAction = toProxy(action);
    if (proxiedAction !== form.action) form.action = proxiedAction;
  }}, true);

  try {{
    window.top.postMessage({{ type: 'proxy-page-title', title: document.title || '' }}, '*');
  }} catch (_) {{}}
}})();
</script>
"""

    if re.search(r"</body>", rewritten, flags=re.IGNORECASE):
        return re.sub(r"</body>", injection + "</body>", rewritten, flags=re.IGNORECASE)
    return rewritten + injection


SHELL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Local Proxy Shell</title>
  <style>
    * { box-sizing: border-box; }
    html, body { margin: 0; width: 100%; height: 100%; background: #0b1020; color: #e5e7eb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
    .app { display: grid; grid-template-rows: auto 1fr; width: 100%; height: 100%; }
    .bar { display: flex; gap: 10px; padding: 10px; border-bottom: 1px solid #1f2a44; background: #0f172a; }
    .input { flex: 1; border: 1px solid #2b3d66; background: #0b1020; color: #e5e7eb; border-radius: 10px; padding: 10px 12px; font-size: 14px; }
    .btn { border: 0; border-radius: 10px; padding: 10px 16px; cursor: pointer; font-weight: 600; color: white; background: linear-gradient(90deg, #0ea5e9, #7c3aed); }
    .hint { margin: 0; padding: 0 10px 10px; color: #94a3b8; font-size: 12px; }
    .frame-wrap { width: 100%; height: 100%; background: #ffffff; }
    iframe { width: 100%; height: 100%; border: 0; display: block; }
  </style>
</head>
<body>
  <div class="app">
    <div>
      <form id="searchForm" class="bar">
        <input id="searchInput" class="input" type="text" autocomplete="off" placeholder="Search with DuckDuckGo or enter a URL" />
        <button class="btn" type="submit">Go</button>
      </form>
    </div>
    <div class="frame-wrap">
      <iframe id="proxyFrame"></iframe>
    </div>
  </div>
  <script>
    const frame = document.getElementById('proxyFrame');
    const form = document.getElementById('searchForm');
    const input = document.getElementById('searchInput');

    function navigate(raw) {
      const q = String(raw || '').trim();
      if (!q) return;
      frame.src = '/open?q=' + encodeURIComponent(q);
      history.replaceState({}, '', '/');
    }

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      navigate(input.value);
    });

    window.addEventListener('message', (event) => {
      if (!event || !event.data || event.data.type !== 'proxy-page-title') return;
      if (event.data.title) document.title = event.data.title + ' - Local Proxy Shell';
    });

    navigate('duckduckgo');
  </script>
</body>
</html>
"""


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "LocalProxy/2.0"

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def _write_bytes(self, status: int, body: bytes, content_type: str) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _serve_shell(self) -> None:
        session_id = self._get_or_create_session_id()
        body = SHELL_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header(
            "Set-Cookie",
            f"{SESSION_COOKIE_NAME}={session_id}; Path=/; HttpOnly; SameSite=Lax",
        )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _serve_error(self, status: int, message: str) -> None:
        payload = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>Proxy Error</title></head><body>"
            f"<h2>Proxy Error</h2><p>{message}</p></body></html>"
        ).encode("utf-8", errors="replace")
        self._write_bytes(status, payload, "text/html; charset=utf-8")

    def _extract_proxy_target(self, parsed) -> str:
        encoded = parsed.path[len("/proxy/") :]
        if not encoded:
            raise ValueError("Missing encoded target URL")
        decoded = decode_url(encoded)
        return safe_join_query(decoded, parsed.query)

    def _get_or_create_session_id(self) -> str:
        cookies = self.headers.get("Cookie", "")
        for item in cookies.split(";"):
            part = item.strip()
            if not part or "=" not in part:
                continue
            key, value = part.split("=", 1)
            if key.strip() == SESSION_COOKIE_NAME and value.strip():
                return value.strip()
        return secrets.token_urlsafe(16)

    def _remember_last_base(self, url: str) -> None:
        session_id = self._get_or_create_session_id()
        with SESSION_LOCK:
            SESSION_LAST_BASE[session_id] = url

    def _resolve_fallback_path_target(self, parsed):
        if parsed.path.startswith("/proxy/"):
            return None
        ref = self.headers.get("Referer", "")
        base = None
        if "/proxy/" in ref:
            try:
                ref_parsed = urlparse(ref)
                encoded = ref_parsed.path.split("/proxy/", 1)[1]
                base = decode_url(encoded)
            except (ValueError, UnicodeDecodeError, IndexError, base64.binascii.Error):
                base = None

        if not base:
            session_id = self._get_or_create_session_id()
            with SESSION_LOCK:
                base = SESSION_LAST_BASE.get(session_id)

        if not base:
            return None

        fallback = urljoin(base, parsed.path)
        fallback = safe_join_query(fallback, parsed.query)
        return fallback

    def _proxy_method(self, method: str) -> None:
        parsed = urlparse(self.path)
        try:
            target_url = self._extract_proxy_target(parsed)
        except (ValueError, UnicodeDecodeError, base64.binascii.Error):
            self._serve_error(400, "Invalid proxy URL encoding.")
            return

        content_length = int(self.headers.get("Content-Length", "0") or "0")
        body_data = self.rfile.read(content_length) if content_length > 0 else None

        request = urllib.request.Request(target_url, data=body_data, method=method) #proxies = proxies

        passthrough_headers = (
            "Accept",
            "Accept-Language",
            "Accept-Charset",
            "Content-Type",
            "Range",
            "If-Modified-Since",
            "If-None-Match",
        )
        for header in passthrough_headers:
            value = self.headers.get(header)
            if value:
                request.add_header(header, value)

        request.add_header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        )
        request.add_header("Accept-Encoding", "gzip, deflate, identity")
        request.add_header("Connection", "keep-alive")
        request.add_header("DNT", "1")
        request.add_header("Upgrade-Insecure-Requests", "1")

        try:
            with OPENER.open(request, timeout=REMOTE_TIMEOUT_SECONDS) as upstream:
                status_code = upstream.getcode()
                response_headers = upstream.headers
                content_type = response_headers.get(
                    "Content-Type", "application/octet-stream"
                )
                lowered_ct = content_type.lower()
                can_rewrite = ("text/html" in lowered_ct) or ("text/css" in lowered_ct)

                body_out = b""
                passthrough_stream = not can_rewrite
                if can_rewrite:
                    raw_content = upstream.read()
                    content_encoding = response_headers.get("Content-Encoding", "").lower()
                    if content_encoding == "gzip":
                        try:
                            raw_content = gzip.decompress(raw_content)
                        except OSError:
                            pass
                    elif content_encoding == "deflate":
                        try:
                            raw_content = zlib.decompress(raw_content, -zlib.MAX_WBITS)
                        except zlib.error:
                            try:
                                raw_content = zlib.decompress(raw_content)
                            except zlib.error:
                                pass
                    elif content_encoding == "br" and brotli is not None:
                        try:
                            raw_content = brotli.decompress(raw_content)
                        except Exception:
                            pass

                    if "text/html" in lowered_ct:
                        html_text = raw_content.decode("utf-8", errors="replace")
                        rewritten = rewrite_html(html_text, target_url)
                        body_out = rewritten.encode("utf-8")
                    elif "text/css" in lowered_ct:
                        css_text = raw_content.decode("utf-8", errors="replace")
                        rewritten_css = rewrite_css(css_text, target_url)
                        body_out = rewritten_css.encode("utf-8")

                self.send_response(status_code)
                if passthrough_stream:
                    allowed_response_headers = (
                        "Content-Type",
                        "Content-Encoding",
                        "Content-Range",
                        "Accept-Ranges",
                        "ETag",
                        "Last-Modified",
                        "Content-Disposition",
                        "Content-Language",
                        "Vary",
                        "Cross-Origin-Resource-Policy",
                    )
                else:
                    allowed_response_headers = (
                        "Content-Type",
                        "Content-Range",
                        "Accept-Ranges",
                        "ETag",
                        "Last-Modified",
                        "Content-Disposition",
                        "Content-Language",
                        "Cross-Origin-Resource-Policy",
                    )
                for header in allowed_response_headers:
                    value = response_headers.get(header)
                    if value:
                        self.send_header(header, value)

                location_header = response_headers.get("Location")
                if location_header:
                    proxied_location = to_proxy_url(target_url, location_header)
                    self.send_header("Location", proxied_location)

                set_cookie_values = response_headers.get_all("Set-Cookie") or []
                for cookie_val in set_cookie_values:
                    self.send_header("Set-Cookie", cookie_val)

                self.send_header("Cache-Control", "no-store, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("X-Frame-Options", "ALLOWALL")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; "
                    "frame-ancestors *;",
                )
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Headers", "*")
                self.send_header("Access-Control-Allow-Methods", "*")
                if passthrough_stream:
                    upstream_len = response_headers.get("Content-Length")
                    if upstream_len:
                        self.send_header("Content-Length", upstream_len)
                else:
                    self.send_header("Content-Length", str(len(body_out)))
                self.end_headers()

                if method != "HEAD":
                    if passthrough_stream:
                        while True:
                            chunk = upstream.read(64 * 1024)
                            if not chunk:
                                break
                            try:
                                self.wfile.write(chunk)
                            except (BrokenPipeError, ConnectionResetError):
                                return
                    else:
                        try:
                            self.wfile.write(body_out)
                        except (BrokenPipeError, ConnectionResetError):
                            return
                self._remember_last_base(target_url)
        except (BrokenPipeError, ConnectionResetError):
            return
        except urllib.error.HTTPError as err:
            error_payload = err.read()
            try:
                self.send_response(err.code)
                err_ct = err.headers.get("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Type", err_ct)
                err_encoding = err.headers.get("Content-Encoding")
                if err_encoding:
                    self.send_header("Content-Encoding", err_encoding)
                self.send_header("Content-Length", str(len(error_payload)))
                self.send_header("Cache-Control", "no-store, max-age=0")
                self.end_headers()
                if method != "HEAD":
                    self.wfile.write(error_payload)
            except (BrokenPipeError, ConnectionResetError):
                return
        except urllib.error.URLError as err:
            self._serve_error(502, f"Upstream connection failed: {err.reason}")
        except (ValueError, zlib.error, OSError) as err:
            self._serve_error(500, f"Proxy processing error: {err}")

    def _serve_open_redirect(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query).get("q", [""])[0]
        destination = normalize_destination(unquote(query))
        location = "/proxy/" + encode_url(destination)
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        parsed = urlparse(self.path)
        if parsed.path in ("", "/"):
            self._serve_shell()
            return
        if parsed.path == "/open":
            self._serve_open_redirect()
            return
        if parsed.path.startswith("/proxy/"):
            self._proxy_method("HEAD")
            return
        fallback_target = self._resolve_fallback_path_target(parsed)
        if fallback_target:
            self.send_response(302)
            self.send_header("Location", "/proxy/" + encode_url(fallback_target))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.end_headers()
            return
        self._serve_error(404, "Route not found.")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("", "/"):
            self._serve_shell()
            return
        if parsed.path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path == "/open":
            self._serve_open_redirect()
            return
        if parsed.path.startswith("/proxy/"):
            self._proxy_method("GET")
            return
        fallback_target = self._resolve_fallback_path_target(parsed)
        if fallback_target:
            self.send_response(302)
            self.send_header("Location", "/proxy/" + encode_url(fallback_target))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.end_headers()
            return
        self._serve_error(404, "Route not found.")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/proxy/"):
            self._proxy_method("POST")
            return
        self._serve_error(404, "Route not found.")

    def do_PUT(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/proxy/"):
            self._proxy_method("PUT")
            return
        self._serve_error(404, "Route not found.")

    def do_PATCH(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/proxy/"):
            self._proxy_method("PATCH")
            return
        self._serve_error(404, "Route not found.")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/proxy/"):
            self._proxy_method("DELETE")
            return
        self._serve_error(404, "Route not found.")


def main():
    server = ThreadingHTTPServer(("localhost", PORT), ProxyHandler)
    print(PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()

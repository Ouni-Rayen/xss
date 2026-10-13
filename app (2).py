"""
Reflected XSS Challenge — "ShopSearch"
=======================================
A deliberately vulnerable product-search page for teaching reflected XSS.

THE BUG (on purpose): /search?q=... takes the query parameter and drops it
straight into the HTML response with no escaping at all. Type ordinary
text and you just see it echoed back. Type an HTML tag — a <script> tag,
an <img onerror=...> — and your browser doesn't display it, it RUNS it,
because as far as the browser is concerned it's just part of the page.

This is a live, real demonstration: visiting
    /search?q=<script>alert(1)</script>
in an actual browser really does pop an alert box. No simulated "admin
bot" is needed for that part — you are the victim, watching it happen in
real time, which is the whole point.

For the CTF-style flag (to match the rest of the workshop's format), the
server also checks, server-side, whether your query actually contains a
working injection vector (a script tag, an event-handler attribute, etc.)
rather than just plain text, and reveals a flag inline when it does.

/search-safe?q=... is the SAME page with the fix applied (HTML-escaped
output), for the "before / after" comparison.

Run locally:
    pip install -r requirements.txt
    python3 app.py
Then open http://127.0.0.1:5000

Deploy: see render.yaml / Procfile in this folder.
"""

from flask import Flask, request, render_template_string
from markupsafe import escape
from urllib.parse import quote
import os
import re

app = Flask(__name__)

FLAG = "FLAG{unescaped_input_becomes_code}"

# If the query contains any of these, it's a real injection vector, not
# just text that happens to contain the word "script". This is a simple,
# server-side stand-in for "did this actually execute" — the real proof is
# the alert box the student sees with their own eyes.
INJECTION_PATTERNS = [
    r"<script", r"onerror\s*=", r"onload\s*=", r"onfocus\s*=",
    r"onmouseover\s*=", r"javascript:", r"<svg", r"<img", r"<iframe",
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)


LAYOUT = """
<!doctype html>
<html><head><title>ShopSearch</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f1216;color:#e8e8e8;max-width:720px;margin:60px auto;padding:0 20px}
a{color:#4fd6c4}
.card{background:#171c22;border:1px solid #262d35;border-radius:12px;padding:28px;margin-top:20px}
input{display:block;width:100%;padding:10px;margin:8px 0 16px;background:#0f1216;border:1px solid #333;color:#eee;border-radius:6px;box-sizing:border-box}
button{background:#4fd6c4;color:#0c2420;border:none;padding:10px 20px;border-radius:6px;font-weight:600;cursor:pointer}
.flag{color:#4fd6c4;font-weight:700;font-size:18px}
.badge{display:inline-block;padding:4px 12px;border-radius:999px;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase}
.vuln{background:#3a1414;color:#ff6b6b}
.safe{background:#123a2e;color:#4fd6c4}
code{background:#0f1216;padding:2px 6px;border-radius:4px}
</style></head>
<body><h1>🛒 ShopSearch</h1>{{ body|safe }}</body></html>
"""

def page(body):
    return render_template_string(LAYOUT, body=body)


def results_block(query, escaped: bool):
    """Build the 'search results' HTML. When escaped=False (the vulnerable
    route) the query is dropped in raw. When escaped=True (the fixed route)
    it goes through markupsafe.escape first, same as any template engine's
    auto-escaping would do."""
    if query is None:
        return ""

    shown = str(escape(query)) if escaped else query  # the one-line difference between vulnerable and fixed

    flag_banner = ""
    if not escaped and INJECTION_RE.search(query):
        flag_banner = f"""
        <div class="card" style="border-color:#4fd6c4">
          <p class="badge safe">Injection confirmed</p>
          <p style="margin-top:14px">Your browser just executed code that came from the URL, not from this site's own developers. That's reflected XSS.</p>
          <p class="flag">{FLAG}</p>
        </div>
        """

    return f"""
    <div class="card">
      <p>No products found for: {shown}</p>
    </div>
    {flag_banner}
    """


@app.route("/")
def index():
    body = """
    <div class="card">
      <p class="badge vuln">Vulnerable</p>
      <h2 style="margin-top:14px">Search ShopSearch</h2>
      <form action="/search" method="get">
        <input name="q" placeholder="Search for a product..." autocomplete="off">
        <button type="submit">Search</button>
      </form>
      <p style="color:#888;font-size:14px;margin-top:16px">
        See the <a href="/search-safe">fixed version</a> for comparison.
      </p>
    </div>
    """
    return page(body)


@app.route("/search")
def search():
    query = request.args.get("q")
    body = f"""
    <div class="card">
      <p class="badge vuln">Vulnerable — /search</p>
      <h2 style="margin-top:14px">Search ShopSearch</h2>
      <form action="/search" method="get">
        <input name="q" value="{query or ''}" placeholder="Search for a product..." autocomplete="off">
        <button type="submit">Search</button>
      </form>
    </div>
    {results_block(query, escaped=False)}
    <p style="margin-top:20px"><a href="/">Back</a> · <a href="/search-safe{'?q=' + quote(query) if query else ''}">See the fixed version with this same query</a></p>
    """
    return page(body)


@app.route("/search-safe")
def search_safe():
    query = request.args.get("q")
    safe_value = str(escape(query)) if query else ""
    body = f"""
    <div class="card">
      <p class="badge safe">Fixed — /search-safe</p>
      <h2 style="margin-top:14px">Search ShopSearch (escaped output)</h2>
      <form action="/search-safe" method="get">
        <input name="q" value="{safe_value}" placeholder="Search for a product..." autocomplete="off">
        <button type="submit">Search</button>
      </form>
    </div>
    {results_block(query, escaped=True)}
    <p style="margin-top:20px"><a href="/">Back</a> · <a href="/search{'?q=' + quote(query) if query else ''}">See the vulnerable version with this same query</a></p>
    """
    return page(body)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"ShopSearch running — http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)

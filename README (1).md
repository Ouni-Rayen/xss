# ShopSearch — Reflected XSS Challenge

A tiny, deliberately vulnerable product-search page for the reflected XSS
section of the workshop. Pairs with the "ShopSearch reflects your query"
slide — this is that exact bug, runnable.

## Deploy on Render (recommended)

1. Push this folder to a GitHub repo (`app.py`, `requirements.txt`,
   `Procfile`, `render.yaml`, `README.md`).
2. On [render.com](https://render.com): **New → Blueprint**, point it at
   the repo. It reads `render.yaml` and sets everything up automatically.
3. Deploy. You get a URL like `https://shopsearch-xss.onrender.com` —
   share that one link with everyone.

This app has no database and keeps no state between requests, so unlike
the IDOR lab it's completely safe to run with more than one worker if you
ever need the capacity — the `Procfile` just keeps 1 for simplicity.

Free-tier note: the service sleeps after 15 minutes idle and takes
~30–60s to wake on the first request — warm it up yourself a few minutes
before the session.

## Run locally instead

```bash
pip install -r requirements.txt
python3 app.py
```

Open `http://127.0.0.1:5000`.

## Student-facing brief

> ShopSearch has a search box at `/search?q=...` that shows you what you
> searched for. Find a way to make your own JavaScript run in your
> browser just by typing something into that search box — no login
> needed. When you succeed, a flag will appear on the page.

## The live demo (do this in front of them first)

1. Go to `/search?q=hello` — it just echoes "No products found for: hello".
   Nothing special yet.
2. Now go to `/search?q=<script>alert(1)</script>` (or type it in the
   search box). **An actual alert box pops up in the browser.** This is
   the moment — stop and let it sink in: the browser didn't display that
   text, it ran it as code. That's reflected XSS, no simulation involved.
3. View the page source (or look in Burp) right after, and point out
   exactly where the raw `<script>` tag landed in the HTML — it's sitting
   right there in the middle of a sentence, completely unescaped.

## Getting the flag

Any of these payloads in the `q` parameter will both pop an alert **and**
trigger the flag, since the server checks (server-side) whether your
query is a real injection vector rather than plain text:

```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

Typing plain text, or even the word "script" without an actual tag,
will **not** trigger the flag — students need an actual working payload,
not just a guess at the keyword.

## The fix, side by side

Visit `/search-safe?q=<script>alert(1)</script>` with the exact same
payload. The page shows the tag as literal text —
`&lt;script&gt;alert(1)&lt;/script&gt;` — instead of running it. Every
page has a link to view the same query on the other route, so you can
flip between vulnerable and fixed live without retyping anything.

## Where the bug lives

In `app.py`, `results_block()`:

```python
shown = str(escape(query)) if escaped else query
```

That's the entire difference between the vulnerable route and the fixed
one. The vulnerable path uses the raw query untouched; the fixed path
runs it through `markupsafe.escape()` first, turning `<` into `&lt;` and
so on — exactly what a template engine's autoescaping does for you by
default, and exactly what gets silently skipped in a real app when a
developer marks a string "safe" (Jinja's `|safe`, or builds HTML with
plain string concatenation like this file deliberately does).

## Notes

- The flag-detection regex (`<script`, `onerror=`, `onload=`, `<svg`,
  `<img`, `<iframe`, `javascript:`) is a simple stand-in for "did this
  actually execute" — the real proof is the alert box itself. It's not a
  security product, just a way to hand out a concrete flag string
  matching the rest of the workshop's CTF format.
- Nothing here needs persistence — there's no database, so a
  Render redeploy or restart changes nothing about the challenge.

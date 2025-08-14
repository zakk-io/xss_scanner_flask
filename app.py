#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
parm.py — Extract same-host params from a page, test each with KnoxSS,
and ONLY output positives where "XSS": "true" in the KnoxSS response.

Now also exposes a Flask GET endpoint so a user can enter a URL in the browser:
  • Run as a web service (recommended for your UI):
        python app.py             # starts Flask on http://127.0.0.1:5001
        # Then call:  GET /xss?url=https://target.tld
  • Or run as CLI (original behavior):
        python app.py -u "https://target.tld" [flags]

Security note: Only scan targets you own or have authorization to test.

Install dependencies:
  pip install flask flask-cors requests beautifulsoup4
"""

import argparse
import concurrent.futures as cf
import html
import json
import random
import re
import string
import sys
import time
from typing import Dict, Set, Tuple, List, Optional
from urllib.parse import (
    urlparse, urlunparse, urljoin, parse_qsl, urlencode, parse_qs, unquote_plus, quote
)

import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from flask_cors import CORS

DEFAULT_UA = "param-knoxss-hits/1.6-singleparam"
KNOXSS_API = "https://api.knoxss.pro"
# Hardcoded KnoxSS API key (as requested)
KNOXSS_KEY = "032e058f-d616-4911-9b7b-5b3fdd640f86"

# URL patterns for discovery
URLISH = re.compile(r'(?:(?:https?:)?//|/|\./|\../|[A-Za-z0-9_.-]+/)[^\s"\']+')
QS_KEY = re.compile(r'[\?&]([A-Za-z0-9_\-\.\[\]]+)=')
HASH_QS = re.compile(r'#.*\?([^#]+)')
# ✅ Fixed: single, valid regex for URLs inside JS strings
SCRIPT_URL = re.compile(r'["\']((?:https?:)?//[^"\']+|\S+?\?\S+?)["\']')

# Heuristic: common system params (still tested, but de-prioritized)
LIKELY_SYSTEM_PARAMS = {
    "csrf", "csrf_token", "xsrf", "authenticity_token", "token",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "mc_eid", "mc_cid", "pxt", "ver", "hash",
}

_rng = random.Random()

def normalize_url(url: str) -> str:
    p = urlparse(url)
    return url if p.scheme else "http://" + url

def parse_all_queries_in_urlish(u: str) -> Set[str]:
    """Extract query keys from normal query (?a=) and from hash-route queries (#...?...)."""
    keys: Set[str] = set()
    if not u:
        return keys
    try:
        p = urlparse(u)
        for k, _ in parse_qsl(p.query, keep_blank_values=True):
            keys.add(k)
        m = HASH_QS.search(u)
        if m:
            frag_q = m.group(1)
            for k, _ in parse_qsl(frag_q, keep_blank_values=True):
                keys.add(k)
    except Exception:
        pass
    return keys

def same_host(target_host: str, cand_host: Optional[str], include_subdomains: bool) -> bool:
    if not cand_host:
        return True  # relative URL -> same host
    if cand_host == target_host:
        return True
    return include_subdomains and cand_host.endswith("." + target_host)

def build_session(headers: Dict[str, str], insecure: bool, timeout: int) -> requests.Session:
    s = requests.Session()
    s.headers.update(headers)
    s.verify = not insecure
    adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=0)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.request_timeout = timeout  # custom marker
    return s

def fetch(session: requests.Session, url: str, verbose: bool) -> Tuple[str, str]:
    """GET the page and return (final_url_after_redirects, html_text)."""
    try:
        r = session.get(url, allow_redirects=True, timeout=session.request_timeout)
        if verbose:
            print(f"[HTTP] GET {r.url} -> {r.status_code} ({len(r.content)} bytes)")
        r.raise_for_status()
        return r.url, r.text
    except requests.RequestException as e:
        raise SystemExit(f"failed_to_fetch: {e}")

def collect_params_with_sources(base_url: str, html_text: str, include_subdomains: bool, verbose: bool=False) -> Dict[str, Set[str]]:
    """
    Return mapping: param_name -> set of ABSOLUTE URLs (same host) where the param appears.
    We'll test each (param, path) combo independently.
    """
    soup = BeautifulSoup(html_text, "html.parser")
    by_param: Dict[str, Set[str]] = {}
    base = urlparse(base_url)
    base_host = base.hostname or ""

    def add(pname: str, abs_url: str):
        by_param.setdefault(pname, set()).add(abs_url)

    def url_allowed(raw_url: str) -> bool:
        abs_url = urljoin(base_url, raw_url)
        h = urlparse(abs_url).hostname
        return same_host(base_host, h, include_subdomains)

    # From final URL after redirects
    for k in parse_all_queries_in_urlish(base_url):
        add(k, base_url)

    # Attributes and inline URL-like values
    for el in soup.find_all(True):
        for _, val in el.attrs.items():
            vals = val if isinstance(val, list) else [val]
            for v in vals:
                if not isinstance(v, str):
                    continue
                # URLs present in attributes
                for url_candidate in URLISH.findall(v):
                    if not url_allowed(url_candidate):
                        continue
                    full = urljoin(base_url, url_candidate)
                    for k in parse_all_queries_in_urlish(full):
                        add(k, full)
                # Raw ?key= patterns (e.g., in onclick)
                for k in QS_KEY.findall(v):
                    add(k, base_url)

    # Forms: include all field names if form action is same host (or empty)
    for form in soup.find_all("form"):
        action = form.get("action")
        action_url = urljoin(base_url, action) if action else base_url
        if not url_allowed(action_url):
            continue
        for inp in form.find_all(["input", "select", "textarea", "button"]):
            nm = inp.get("name")
            if nm:
                add(nm, action_url)

    # Inline scripts: URLs & raw ?key=, host-filtered
    for s in soup.find_all("script"):
        txt = s.string or s.get_text() or ""
        if not txt:
            continue
        for u in SCRIPT_URL.findall(txt):
            if not url_allowed(u):
                continue
            full = urljoin(base_url, u)
            for k in parse_all_queries_in_urlish(full):
                add(k, full)
        for k in QS_KEY.findall(txt):
            add(k, base_url)

    if verbose:
        base_host_info = f"{base_host} (include_subdomains={include_subdomains})"
        print(f"[DISCOVER] Target host: {base_host_info}")
        for pname, urls in by_param.items():
            paths = sorted({urlparse(u).path or "/" for u in urls})
            mark = " (systemish)" if pname.lower() in LIKELY_SYSTEM_PARAMS else ""
            print(f"[DISCOVER] {pname}: paths={paths}{mark}")

    return by_param

def build_seeded_target_for_param(source_url: str, param: str, seed_value: str) -> str:
    """
    Build a test URL that contains ONLY the tested parameter (no other params).
    If the param exists in the source URL, preserve its value; otherwise use seed_value.
    """
    p = urlparse(source_url)
    qs = dict(parse_qsl(p.query, keep_blank_values=True))
    if param in qs and qs[param] not in (None, ""):
        v = qs[param]
    else:
        v = seed_value
    # IMPORTANT: only keep this single parameter in the query (no '&')
    new_q = {param: v}
    clean = p._replace(query=urlencode(new_q, doseq=True), fragment="")
    return urlunparse(clean)

def _jittered_sleep(base: float, attempt: int):
    # Exponential backoff with jitter
    t = base * (2 ** attempt) * (0.5 + _rng.random())
    time.sleep(min(t, 5.0))

def knoxss_check(session: requests.Session, target_url: str, retries: int, backoff: float, verbose: bool=False) -> dict:
    """Call KnoxSS API and return its JSON (or an error object). Retries on transient failures."""
    headers = {"X-API-KEY": KNOXSS_KEY, "User-Agent": DEFAULT_UA}
    data = {"target": target_url}
    for attempt in range(retries + 1):
        try:
            resp = session.post(KNOXSS_API, headers=headers, data=data, timeout=session.request_timeout)
            if verbose:
                print(f"[KNOXSS] {resp.status_code} target={target_url}")
            try:
                return resp.json()
            except ValueError:
                return {"error": f"non_json_response (HTTP {resp.status_code})", "Target": target_url}
        except requests.RequestException as e:
            if attempt >= retries:
                return {"error": f"request_error: {e}", "Target": target_url}
            _jittered_sleep(backoff, attempt)
    return {"error": "unknown_error", "Target": target_url}

def merge_cookie(existing_cookie_header, cookie_flag_value):
    """
    Merge a Cookie header from -H "Cookie: ..." and --cookie "a=b; c=d".
    If both exist, concatenate with '; ' ensuring proper separation.
    """
    if not existing_cookie_header and not cookie_flag_value:
        return None
    if existing_cookie_header and not cookie_flag_value:
        return existing_cookie_header.strip()
    if cookie_flag_value and not existing_cookie_header:
        return cookie_flag_value.strip()
    # both present
    left = existing_cookie_header.strip().rstrip(";")
    right = cookie_flag_value.strip().lstrip(";").strip()
    if not left:
        return right
    if not right:
        return left
    return f"{left}; {right}"

def _rand_tag(n: int = 8) -> str:
    chars = string.ascii_letters + string.digits
    return "__kxss_" + "".join(_rng.choice(chars) for _ in range(n)) + "__"

# -------- Precheck & PoC verification (follow redirects) --------

def _follow_get(session: requests.Session, url: str, max_hops: int = 3):
    """
    Follow up to max_hops redirects manually to inspect each response.
    Returns (responses_list, final_url).
    """
    out = []
    cur = url
    for _ in range(max_hops + 1):
        r = session.get(cur, allow_redirects=False, timeout=session.request_timeout)
        out.append(r)
        loc = r.headers.get("Location")
        if not loc or not (300 <= r.status_code < 400):
            break
        cur = urljoin(cur, loc)
    return out, cur

def _find_reflection_markers_in_chain(responses: List[requests.Response], value: str) -> Tuple[bool, str]:
    if not value:
        return False, "none"
    candidates = {value, unquote_plus(value), html.escape(value)}
    try:
        candidates.add(quote(unquote_plus(value), safe=""))
    except Exception:
        pass
    for r in responses:
        loc = r.headers.get("Location", "")
        for c in candidates:
            if c and c in loc:
                return True, "header"
    for r in responses:
        body = r.text
        for c in candidates:
            if c and c in body:
                return True, "body"
    return False, "none"

def reflection_precheck(session: requests.Session, target_url: str, param_name: str, seed_value: str, verbose: bool=False) -> bool:
    """
    Precheck that inserts a unique tag into the tested param and looks for reflection
    across up to 3 redirect hops. Used for soft/aggressive modes.
    """
    tag = _rand_tag()
    try:
        p = urlparse(target_url)
        qs = dict(parse_qsl(p.query, keep_blank_values=True))
        qs[param_name] = tag
        test_url = p._replace(query=urlencode(qs, doseq=True)).geturl()
        chain, _ = _follow_get(session, test_url, max_hops=3)
        if verbose:
            print(f"[PRECHECK] chain_len={len(chain)} {test_url}")
        found, _ = _find_reflection_markers_in_chain(chain, tag)
        return found
    except requests.RequestException:
        # Don't exclude on network errors
        return True

def _maybe_unescape_poc(poc_val: str) -> str:
    """
    KnoxSS sometimes returns a quoted string with escapes. Try to normalize:
    - Strip surrounding quotes if present
    - Unescape backslash escapes and HTML entities
    """
    if not isinstance(poc_val, str):
        return ""
    s = poc_val.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1]
    s = s.replace("\\/", "/").replace('\\"', '"').replace("\\'", "'")
    s = html.unescape(s)
    return s

def _extract_param_and_value_from_url(url_str: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        p = urlparse(url_str)
        q = parse_qs(p.query, keep_blank_values=True)
        for k, vals in q.items():
            if vals:
                return k, vals[0]
        return None, None
    except Exception:
        return None, None

def _context_heuristics(body: str) -> Tuple[bool, List[str]]:
    """
    Very lightweight hints that page may be permissive to inline script/svg/event handlers.
    """
    hints = []
    lowered = body.lower()
    risky = False
    if "<script" in lowered:
        hints.append("script_tag_present")
    if any(ev in lowered for ev in ("onload=", "onerror=", "onclick=", "onmouseover=")):
        hints.append("event_handlers_present")
        risky = True
    if "<svg" in lowered:
        hints.append("svg_present")
        risky = True
    if "http-equiv=\"content-security-policy\"" in lowered:
        hints.append("meta_csp_present")
    return risky, hints

def verify_poc(session: requests.Session, knoxss_target: str, knoxss_res: dict, verbose: bool=False) -> dict:
    """
    Attempts to verify confidence of a KnoxSS 'XSS:true' hit.
    Returns dict with fields:
      verified_reflection (bool)
      reflection_location ('body'|'header'|'none')
      csp_present (bool)
      confidence ('high'|'medium'|'low')
      notes (list[str])
    """
    notes: List[str] = []
    poc_raw = knoxss_res.get("PoC")
    poc_url = _maybe_unescape_poc(poc_raw or "")
    knoxss_error = str(knoxss_res.get("Error", "") or "")
    notes.append(f"knoxss_error={knoxss_error}" if knoxss_error else "knoxss_error=none")

    parsed_poc = urlparse(poc_url) if poc_url else None
    if not parsed_poc or not parsed_poc.scheme or not parsed_poc.netloc:
        try:
            chain, _ = _follow_get(session, knoxss_target, max_hops=3)
            t_parsed = urlparse(knoxss_target)
            qs = parse_qs(t_parsed.query, keep_blank_values=True)
            val = ""
            if qs:
                _, vs = next(iter(qs.items()))
                val = vs[0] if isinstance(vs, list) and vs else ""
            reflection, where = _find_reflection_markers_in_chain(chain, val)
            csp = any("Content-Security-Policy" in r.headers for r in chain)
            risky, hints = _context_heuristics(chain[-1].text if chain else "")
            if reflection and (risky or not knoxss_error):
                conf = "high"
            elif reflection:
                conf = "medium"
            else:
                conf = "low" if "fp warning" in knoxss_error.lower() else "medium"
            return {
                "verified_reflection": reflection,
                "reflection_location": where,
                "csp_present": csp,
                "confidence": conf,
                "notes": notes + (["heuristics=" + ",".join(hints)] if hints else [])
            }
        except requests.RequestException:
            return {
                "verified_reflection": False,
                "reflection_location": "none",
                "csp_present": False,
                "confidence": "low" if "fp warning" in knoxss_error.lower() else "medium",
                "notes": notes + ["fetch_error_on_target"]
            }

    _, poc_value = _extract_param_and_value_from_url(poc_url)
    try:
        chain, _ = _follow_get(session, poc_url, max_hops=3)
        reflection, where = _find_reflection_markers_in_chain(chain, poc_value or "")
        csp_present = any("Content-Security-Policy" in r.headers for r in chain)
        risky, hints = _context_heuristics(chain[-1].text if chain else "")

        if reflection and (risky or not knoxss_error):
            confidence = "high"
        elif reflection:
            confidence = "medium"
        else:
            confidence = "low" if "fp warning" in knoxss_error.lower() else "medium"

        return {
            "verified_reflection": reflection,
            "reflection_location": where,
            "csp_present": csp_present,
            "confidence": confidence,
            "notes": notes + (["heuristics=" + ",".join(hints)] if hints else [])
        }
    except requests.RequestException as e:
        return {
            "verified_reflection": False,
            "reflection_location": "none",
            "csp_present": False,
            "confidence": "low" if "fp warning" in knoxss_error.lower() else "medium",
            "notes": notes + [f"fetch_error_on_poc={e.__class__.__name__}"]
        }

def decide_workers(user_workers: Optional[int]) -> int:
    if user_workers and user_workers > 0:
        return user_workers
    try:
        import multiprocessing
        cpu = max(1, multiprocessing.cpu_count())
        return min(32, cpu * 5)
    except Exception:
        return 8

# ----------------- Core scan runner (shared by CLI & Flask) -----------------

def scan_with_options(
    url: str,
    *,
    include_subdomains: bool = False,
    header_list: Optional[List[str]] = None,
    cookie: Optional[str] = None,
    insecure: bool = False,
    verbose: bool = False,
    timeout: int = 20,
    max_workers: int = 0,
    retries: int = 2,
    backoff: float = 0.6,
    require_poc: bool = False,
    seed: str = "1",
    precheck: str = "soft",
    no_verify_poc: bool = False,
    strict: bool = False,
) -> dict:
    # Headers
    page_headers: Dict[str, str] = {"User-Agent": DEFAULT_UA}
    user_cookie_from_H = None
    for h in header_list or []:
        if ":" in h:
            k, v = h.split(":", 1)
            if k.strip().lower() == "cookie":
                user_cookie_from_H = v.strip()
            else:
                page_headers[k.strip()] = v.strip()
    merged_cookie = merge_cookie(user_cookie_from_H, cookie)
    if merged_cookie:
        page_headers["Cookie"] = merged_cookie

    session = build_session(page_headers, insecure, timeout)

    # 1) Fetch
    base_url = normalize_url(url)
    final_url, html_text = fetch(session, base_url, verbose=verbose)
    base_host = urlparse(final_url).hostname or ""

    # 2) Collect
    param_sources = collect_params_with_sources(final_url, html_text, include_subdomains=include_subdomains, verbose=verbose)

    # 3) Build unique seeded targets (single param per URL)
    targets: List[Tuple[str, str]] = []
    seen_targets = set()
    for pname, urls in param_sources.items():
        urls_sorted = sorted(urls)
        if pname.lower() in LIKELY_SYSTEM_PARAMS and len(urls_sorted) > 8:
            urls_sorted = urls_sorted[:8]
        for src in urls_sorted:
            t = build_seeded_target_for_param(src, pname, seed)
            if t in seen_targets:
                continue
            seen_targets.add(t)
            targets.append((pname, t))

    if verbose:
        print(f"[PLAN] Unique combos to test: {len(targets)}")

    # 4) Precheck (off/soft/aggressive)
    reflective_ok: Dict[Tuple[str, str], bool] = {}
    if precheck != "off" and targets:
        if verbose:
            print(f"[PRECHECK] mode={precheck}")
        pre_workers = min(decide_workers(max_workers), 16)
        with cf.ThreadPoolExecutor(max_workers=pre_workers) as exe:
            futs = {exe.submit(reflection_precheck, session, tgt, pname, seed, verbose): (pname, tgt)
                    for pname, tgt in targets}
            for fut in cf.as_completed(futs):
                pname, tgt = futs[fut]
                try:
                    reflective_ok[(pname, tgt)] = fut.result()
                except Exception:
                    reflective_ok[(pname, tgt)] = True

    # 5) KnoxSS checks concurrently
    tested = 0
    raw_hits: List[dict] = []
    workers = decide_workers(max_workers)

    def worker(pname: str, target: str) -> Optional[dict]:
        nonlocal tested
        is_reflective = reflective_ok.get((pname, target), True)
        if precheck == "aggressive" and not is_reflective:
            if verbose:
                print(f"[SKIP ] precheck failed: {target} param={pname}")
            return None

        res = knoxss_check(session, target, retries=retries, backoff=backoff, verbose=verbose)
        tested += 1
        is_xss = str(res.get("XSS", "")).lower() == "true"
        has_poc = bool(res.get("PoC"))
        if not is_xss:
            return None
        if require_poc and not has_poc:
            return None

        p = urlparse(target)
        hit = {
            "param": pname,
            "path": p.path or "/",
            "target": res.get("Target", target),
            "poc": res.get("PoC"),
            "redir": res.get("Redir"),
            "timestamp": res.get("Timestamp"),
            "elapsed": res.get("Time Elapsed"),
            "version": res.get("Version"),
            "api_call": res.get("API Call"),
            "knoxss_error": res.get("Error") or "",
            "precheck_reflective": is_reflective if precheck != "off" else None
        }

        if not no_verify_poc:
            ver = verify_poc(session, target, res, verbose=verbose)
            hit.update(ver)
        else:
            err = str(res.get("Error", "") or "")
            conf = "medium" if "fp warning" not in err.lower() else "low"
            hit.update({
                "verified_reflection": None,
                "reflection_location": "none",
                "csp_present": None,
                "confidence": conf,
                "notes": ["verify_poc_skipped"]
            })

        return hit

    if targets:
        if verbose:
            print(f"[SCAN ] Submitting {len(targets)} targets to KnoxSS with {workers} workers...")
        with cf.ThreadPoolExecutor(max_workers=workers) as exe:
            futs = {exe.submit(worker, pname, tgt): (pname, tgt) for pname, tgt in targets}
            for fut in cf.as_completed(futs):
                try:
                    hit = fut.result()
                    if hit:
                        raw_hits.append(hit)
                except Exception as e:
                    if verbose:
                        pname, tgt = futs[fut]
                        print(f"[ERROR] {e} on {tgt} ({pname})")

    # 6) Strict filter (optional)
    hits: List[dict] = []
    if strict:
        for h in raw_hits:
            err = (h.get("knoxss_error") or "").lower()
            conf = (h.get("confidence") or "").lower()
            if "fp warning" in err and conf != "high":
                continue
            hits.append(h)
    else:
        hits = raw_hits

    # 7) Output — clean JSON with only hits
    summary = {
        "page": final_url,
        "host": base_host,
        "params_found": len(param_sources),
        "combos_tested": tested,
        "hits_count": len(hits),
        "hits": hits
    }

    return summary

# --------------------------- Flask HTTP interface ---------------------------

app = Flask(__name__)
CORS(app)

def _to_bool(v: Optional[str], default: bool = False) -> bool:
    if v is None:
        return default
    return str(v).lower() in {"1", "true", "yes", "on"}

@app.get("/xss")
def xss_scan_endpoint():
    url = request.args.get("url") or request.args.get("u")
    if not url:
        return jsonify({"error": "missing required query parameter 'url'"}), 400

    try:
        summary = scan_with_options(
            url=url,
            include_subdomains=_to_bool(request.args.get("include_subdomains"), False),
            header_list=request.args.getlist("H") or request.args.getlist("header"),
            cookie=request.args.get("cookie"),
            insecure=_to_bool(request.args.get("insecure"), False),
            verbose=_to_bool(request.args.get("verbose"), False),
            timeout=int(request.args.get("timeout", 20)),
            max_workers=int(request.args.get("max_workers", 0)),
            retries=int(request.args.get("retries", 2)),
            backoff=float(request.args.get("backoff", 0.6)),
            require_poc=_to_bool(request.args.get("require_poc"), False),
            seed=request.args.get("seed", "1"),
            precheck=request.args.get("precheck", "soft"),
            no_verify_poc=_to_bool(request.args.get("no_verify_poc"), False),
            strict=_to_bool(request.args.get("strict"), False),
        )
        return jsonify(summary)
    except SystemExit as e:
        # wrap fetch() failures, etc.
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        return jsonify({"error": "internal_error", "details": str(e)}), 500

# ------------------------------ CLI entrypoint ------------------------------

def cli_main():
    ap = argparse.ArgumentParser(description="Extract same-host params, test with KnoxSS, show ONLY XSS:true hits (single-param tests, verified).")
    ap.add_argument("-u", "--url", required=True, help="Target page URL")
    ap.add_argument("--include-subdomains", action="store_true", help="Also include params from subdomains")
    ap.add_argument("-H", "--header", action="append", dest="header_list",
                    help='Repeatable. Example: -H "Authorization: Bearer XXX"')
    ap.add_argument("--cookie", help='Convenience flag to set Cookie header, e.g. --cookie "a=b; c=d"')
    ap.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification")
    ap.add_argument("--verbose", action="store_true", help="Verbose logging")
    ap.add_argument("-o", "--output", help="Write JSON results to file")

    # Performance & accuracy
    ap.add_argument("--timeout", type=int, default=20, help="HTTP timeout seconds (default: 20)")
    ap.add_argument("--max-workers", type=int, default=0, help="Max concurrent KnoxSS checks (default: auto)")
    ap.add_argument("--retries", type=int, default=2, help="KnoxSS retry attempts (default: 2)")
    ap.add_argument("--backoff", type=float, default=0.6, help="Base backoff seconds with jitter (default: 0.6)")
    ap.add_argument("--require-poc", action="store_true", help="Require PoC from KnoxSS to count as hit")

    # Seeding & precheck
    ap.add_argument("--seed", default="1", help="Seed value for params if no original value (default: 1)")
    ap.add_argument("--precheck", choices=["off", "soft", "aggressive"], default="soft",
                    help="Reflection precheck mode: off|soft|aggressive (default: soft)")

    # Verification & strictness
    ap.add_argument("--no-verify-poc", action="store_true", help="Skip PoC verification step")
    ap.add_argument("--strict", action="store_true",
                    help="Drop hits with KnoxSS FP warning unless verification is HIGH")

    args = ap.parse_args()

    summary = scan_with_options(
        url=args.url,
        include_subdomains=args.include_subdomains,
        header_list=args.header_list,
        cookie=args.cookie,
        insecure=args.insecure,
        verbose=args.verbose,
        timeout=args.timeout,
        max_workers=args.max_workers,
        retries=args.retries,
        backoff=args.backoff,
        require_poc=args.require_poc,
        seed=args.seed,
        precheck=args.precheck,
        no_verify_poc=args.no_verify_poc,
        strict=args.strict,
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"[+] Saved to {args.output}")
    else:
        print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    # If invoked with -u/--url, run the CLI; otherwise, start the Flask server.
    if any(a in sys.argv for a in ("-u", "--url")):
        cli_main()
    else:
        # Run Flask dev server on port 5001 to avoid conflicts (e.g., with Burp on 8080)
        app.run(host="0.0.0.0", port=5001, debug=True)

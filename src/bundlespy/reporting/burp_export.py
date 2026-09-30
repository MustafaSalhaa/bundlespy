"""
Burp Suite Export Module.

Exports discovered endpoints and URLs into Burp Suite compatible formats:
- Burp sitemap XML (importable via Project > Import)
- Simple URL list (usable with Burp Intruder/Scanner)
"""

import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
from base64 import b64encode
from urllib.parse import urlparse, urlencode

from ..storage.models import ScanResult, Endpoint


def _build_request(parsed, method: str, ep: Endpoint = None) -> bytes:
    """
    Build a realistic HTTP/1.1 request for a discovered endpoint.

    For POST/PUT/PATCH endpoints with body_fields, generates a JSON body.
    For endpoints with query_params and a GET method, appends them to the path.
    """
    method  = (method or "GET").upper()
    path    = parsed.path or "/"
    host    = parsed.netloc

    # Reconstruct query string from known param names
    query_params = getattr(ep, "query_params", []) or []
    if query_params and method == "GET":
        qs = "&".join(
            f"{p.get('name', 'param')}=" for p in query_params if p.get("name")
        )
        if qs:
            path = f"{path}?{qs}"
    elif parsed.query:
        path = f"{path}?{parsed.query}"

    # Body fields for mutation methods
    body_fields = getattr(ep, "body_fields", []) or []
    body = b""
    content_type_header = ""

    if method in ("POST", "PUT", "PATCH") and body_fields:
        # Build a skeleton JSON body from discovered field names
        payload = {f.get("name", "field"): "" for f in body_fields if f.get("name")}
        body = json.dumps(payload, separators=(",", ":")).encode()
        content_type_header = f"Content-Type: application/json\r\nContent-Length: {len(body)}"
    elif method in ("POST", "PUT", "PATCH"):
        # Mutation endpoint but no body fields known — send empty JSON
        body = b"{}"
        content_type_header = f"Content-Type: application/json\r\nContent-Length: {len(body)}"

    # Build headers block
    extra_headers = ""
    if content_type_header:
        extra_headers = f"{content_type_header}\r\n"

    # Auth context hint (e.g. bearer token placeholder)
    auth_ctx = getattr(ep, "auth_context", "") or ""
    if auth_ctx and "bearer" in auth_ctx.lower():
        extra_headers += "Authorization: Bearer <token>\r\n"

    request_line = f"{method} {path} HTTP/1.1\r\n"
    headers = (
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36\r\n"
        f"Accept: application/json, text/html, */*\r\n"
        f"Accept-Language: en-US,en;q=0.9\r\n"
        f"Connection: close\r\n"
        f"{extra_headers}"
        f"\r\n"
    )
    raw = (request_line + headers).encode() + body
    return raw


def generate_burp_xml(result: ScanResult) -> str:
    """
    Generate Burp Suite sitemap XML from scan results.

    Each endpoint entry uses the correct HTTP method and includes a request
    body skeleton for POST/PUT/PATCH endpoints with discovered body fields.
    Format compatible with Burp Suite Professional and Community Edition.
    """
    root = ET.Element("items", burpVersion="2024.1", exportTime="BundleSpy Export")

    seen = set()

    # ── Endpoints — main attack surface ──────────────────────────────────────
    for ep in result.endpoints:
        url = ep.url
        if not url.startswith("http") or url in seen:
            continue
        seen.add(url)

        try:
            parsed = urlparse(url)
            method = (ep.method or "GET").upper()
            if method in ("UNKNOWN", ""):
                method = "GET"

            raw_request = _build_request(parsed, method, ep)

            item = ET.SubElement(root, "item")
            ET.SubElement(item, "time").text   = "0"
            ET.SubElement(item, "url").text    = url
            ET.SubElement(item, "host", ip="").text = parsed.netloc
            ET.SubElement(item, "port").text   = str(
                parsed.port or (443 if parsed.scheme == "https" else 80)
            )
            ET.SubElement(item, "protocol").text = parsed.scheme
            ET.SubElement(item, "method").text   = method
            ET.SubElement(item, "path").text     = parsed.path or "/"
            ET.SubElement(item, "extension")

            ET.SubElement(item, "request", base64="true").text = (
                b64encode(raw_request).decode()
            )
            ET.SubElement(item, "status").text         = ""
            ET.SubElement(item, "responselength").text  = "0"
            ET.SubElement(item, "mimetype").text        = ""
            ET.SubElement(item, "response", base64="true").text = ""

            # Annotate with BundleSpy metadata so analysts know what was found
            category = getattr(ep, "category", "") or ""
            kind     = getattr(ep, "kind", "") or ""
            comment  = f"BundleSpy: {category}"
            if kind and kind not in category.lower():
                comment += f" ({kind})"
            if getattr(ep, "auth_context", ""):
                comment += f" | auth: {ep.auth_context}"
            ET.SubElement(item, "comment").text = comment
        except Exception:
            continue

    # ── JS files — secondary coverage ─────────────────────────────────────────
    for js in result.js_files:
        url = js.url
        if not url.startswith("http") or url in seen:
            continue
        seen.add(url)

        try:
            parsed = urlparse(url)
            raw_request = _build_request(parsed, "GET")

            item = ET.SubElement(root, "item")
            ET.SubElement(item, "time").text   = "0"
            ET.SubElement(item, "url").text    = url
            ET.SubElement(item, "host", ip="").text = parsed.netloc
            ET.SubElement(item, "port").text   = str(
                parsed.port or (443 if parsed.scheme == "https" else 80)
            )
            ET.SubElement(item, "protocol").text  = parsed.scheme
            ET.SubElement(item, "method").text    = "GET"
            ET.SubElement(item, "path").text      = parsed.path or "/"
            ET.SubElement(item, "extension")

            ET.SubElement(item, "request", base64="true").text = (
                b64encode(raw_request).decode()
            )
            ET.SubElement(item, "status").text         = ""
            ET.SubElement(item, "responselength").text  = "0"
            ET.SubElement(item, "mimetype").text        = "script"
            ET.SubElement(item, "response", base64="true").text = ""
            ET.SubElement(item, "comment").text = "BundleSpy: JS file"
        except Exception:
            continue

    # Pretty print
    raw = ET.tostring(root, encoding="unicode")
    try:
        pretty = minidom.parseString(raw).toprettyxml(indent="  ")
        lines  = pretty.split("\n")
        return "\n".join(lines[1:])  # strip XML declaration
    except Exception:
        return raw


def generate_url_list(result: ScanResult) -> str:
    """
    Generate a plain URL list for use with Burp Intruder or other tools.
    One URL per line, deduplicated and sorted, endpoints before JS files.
    """
    seen = set()
    ep_urls = []
    js_urls = []

    for ep in result.endpoints:
        if ep.url.startswith("http") and ep.url not in seen:
            ep_urls.append(ep.url)
            seen.add(ep.url)

    for js in result.js_files:
        if js.url.startswith("http") and js.url not in seen:
            js_urls.append(js.url)
            seen.add(js.url)

    lines = sorted(ep_urls) + sorted(js_urls)
    return "\n".join(lines)

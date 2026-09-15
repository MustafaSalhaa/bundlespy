"""
Attack Surface Analysis.

Takes all discovered endpoints and highlights the security-relevant surface:
- IDOR candidates (numeric ID parameters)
- Injectable parameters (search, query, filter)
- File operation endpoints (upload/download/path)
- Authentication endpoints
- Admin endpoints
- State-changing endpoints (POST/PUT/DELETE)
- Parameters worth fuzzing
"""

import re
from typing import List, Dict
from dataclasses import dataclass, field


# Parameters commonly vulnerable to IDOR
IDOR_PARAM_HINTS = {
    "id", "userid", "user_id", "uid", "productid", "product_id",
    "orderid", "order_id", "postid", "post_id", "accountid",
    "account_id", "docid", "doc_id", "fileid", "file_id", "itemid",
    "item_id", "cartid", "cart_id", "invoiceid", "customerid",
    "messageid", "ticketid", "recordid", "num", "no", "key",
}

# Parameters commonly vulnerable to injection
INJECTION_PARAM_HINTS = {
    "q", "query", "search", "searchterm", "keyword", "keywords",
    "filter", "sort", "order", "orderby", "s", "term", "name",
    "email", "username", "url", "redirect", "return", "returnurl",
    "next", "callback", "path", "file", "page", "lang", "locale",
    "category", "type", "format", "view", "template", "include",
}

# Parameters that suggest file operations (LFI/path traversal)
FILE_PARAM_HINTS = {
    "file", "filename", "path", "filepath", "dir", "directory",
    "folder", "download", "upload", "doc", "document", "attachment",
    "include", "template", "page", "load", "read", "src", "source",
}

# Parameters that suggest SSRF
SSRF_PARAM_HINTS = {
    "url", "uri", "link", "src", "source", "redirect", "return",
    "returnurl", "next", "callback", "webhook", "proxy", "fetch",
    "load", "domain", "host", "site", "target", "dest", "destination",
}

# Parameters that suggest open redirect
REDIRECT_PARAM_HINTS = {
    "redirect", "return", "returnurl", "return_url", "next", "url",
    "goto", "dest", "destination", "continue", "redir", "redirect_uri",
    "callback", "forward",
}


@dataclass
class AttackSurfaceItem:
    endpoint_url:  str
    method:        str
    param_name:    str
    vuln_class:    str    # IDOR / INJECTION / LFI / SSRF / OPEN_REDIRECT
    reason:        str
    priority:      str    # HIGH / MEDIUM / LOW
    source_file:   str


def analyze_attack_surface(endpoints: List) -> Dict:
    """
    Analyze all endpoints and extract the security-relevant attack surface.
    Returns categorized attack surface for a pentester.
    """
    idor:          List[AttackSurfaceItem] = []
    injection:     List[AttackSurfaceItem] = []
    file_ops:      List[AttackSurfaceItem] = []
    ssrf:          List[AttackSurfaceItem] = []
    open_redirect: List[AttackSurfaceItem] = []
    state_change:  List = []   # POST/PUT/DELETE endpoints
    auth_surface:  List = []
    admin_surface: List = []
    seen_params:   set  = set()

    for ep in endpoints:
        method = (ep.method or "UNKNOWN").upper()
        url    = ep.url

        # State-changing methods are always interesting
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            state_change.append(ep)

        # Auth and admin surface
        if ep.category == "AUTH":
            auth_surface.append(ep)
        elif ep.category == "ADMIN":
            admin_surface.append(ep)

        # Analyze each parameter
        all_params = []
        for qp in (getattr(ep, "query_params", None) or []):
            all_params.append(("query", qp.get("name", "")))
        for pp in (getattr(ep, "path_params", None) or []):
            all_params.append(("path", pp.get("name", "")))
        for bf in (getattr(ep, "body_fields", None) or []):
            all_params.append(("body", bf.get("name", "")))

        for location, pname in all_params:
            if not pname:
                continue
            plower = pname.lower().replace("-", "").replace("_", "")
            dedup_key = f"{url}:{pname}"

            # IDOR — numeric ID params
            if plower in {p.replace("_", "") for p in IDOR_PARAM_HINTS} or plower.endswith("id"):
                key = f"idor:{ep.path}:{pname}"
                if key not in seen_params:
                    seen_params.add(key)
                    idor.append(AttackSurfaceItem(
                        url, method, pname, "IDOR",
                        f"{location} param '{pname}' looks like an object reference",
                        "HIGH", ep.source_file,
                    ))

            # Injection
            if plower in {p.replace("_", "") for p in INJECTION_PARAM_HINTS}:
                key = f"inj:{ep.path}:{pname}"
                if key not in seen_params:
                    seen_params.add(key)
                    injection.append(AttackSurfaceItem(
                        url, method, pname, "INJECTION",
                        f"{location} param '{pname}' may be injectable (SQLi/XSS)",
                        "HIGH", ep.source_file,
                    ))

            # File operations
            if plower in {p.replace("_", "") for p in FILE_PARAM_HINTS}:
                key = f"lfi:{ep.path}:{pname}"
                if key not in seen_params:
                    seen_params.add(key)
                    file_ops.append(AttackSurfaceItem(
                        url, method, pname, "LFI/PATH",
                        f"{location} param '{pname}' may allow path traversal or LFI",
                        "HIGH", ep.source_file,
                    ))

            # SSRF
            if plower in {p.replace("_", "") for p in SSRF_PARAM_HINTS}:
                key = f"ssrf:{ep.path}:{pname}"
                if key not in seen_params:
                    seen_params.add(key)
                    ssrf.append(AttackSurfaceItem(
                        url, method, pname, "SSRF",
                        f"{location} param '{pname}' may allow SSRF",
                        "MEDIUM", ep.source_file,
                    ))

            # Open redirect
            if plower in {p.replace("_", "") for p in REDIRECT_PARAM_HINTS}:
                key = f"redir:{ep.path}:{pname}"
                if key not in seen_params:
                    seen_params.add(key)
                    open_redirect.append(AttackSurfaceItem(
                        url, method, pname, "OPEN_REDIRECT",
                        f"{location} param '{pname}' may allow open redirect",
                        "MEDIUM", ep.source_file,
                    ))

    return {
        "idor":          idor,
        "injection":     injection,
        "file_ops":      file_ops,
        "ssrf":          ssrf,
        "open_redirect": open_redirect,
        "state_change":  state_change,
        "auth_surface":  auth_surface,
        "admin_surface": admin_surface,
        "total_items":   len(idor) + len(injection) + len(file_ops)
                       + len(ssrf) + len(open_redirect),
    }

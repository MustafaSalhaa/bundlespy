"""
Boot-time configuration extraction.

Parses window.__CONFIG__, window.APP_CONFIG, window.env, window.ENV,
serialized framework state, and API base URLs from already-collected
HTML and JavaScript content.

No new network requests are made. Everything here works on content
that was already fetched during the normal collection phase.
"""

import re
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin

logger = logging.getLogger("bundlespy.analysis.boot_config")

# ── Patterns for common config globals ───────────────────────────────────────

# window.__CONFIG__ = {...} or window.__CONFIG__={...}
_RE_CONFIG_GLOBALS = re.compile(
    r'(?:window|globalThis|self)\.'
    r'((?:__)?(?:CONFIG|APP_CONFIG|ENV|APP_ENV|RUNTIME_CONFIG|SETTINGS|'
    r'PUBLIC_CONFIG|CLIENT_CONFIG|SITE_CONFIG|INIT_DATA|BOOT_DATA|'
    r'APP_SETTINGS|FEATURE_FLAGS|FLAGS)(?:__)?)'
    r'\s*=\s*(\{[^;]{0,20000})',
    re.IGNORECASE | re.DOTALL,
)

# var/const/let CONFIG = {...} at module top level
_RE_MODULE_CONFIG = re.compile(
    r'(?:var|const|let)\s+'
    r'(CONFIG|APP_CONFIG|ENV|RUNTIME_CONFIG|SETTINGS|FEATURE_FLAGS|FLAGS)'
    r'\s*=\s*(\{[^;]{0,20000})',
    re.IGNORECASE | re.DOTALL,
)

# window.env.API_URL = "..." (individual property assignments)
_RE_ENV_PROP = re.compile(
    r'(?:window|globalThis|self)\.(?:env|ENV|config|CONFIG)'
    r'\s*\.\s*([A-Z_][A-Z0-9_]{1,80})'
    r'\s*=\s*["\x27`]([^"\x27`]{1,512})["\x27`]',
    re.IGNORECASE,
)

# process.env.REACT_APP_API_URL = "..." (Next.js / CRA patterns baked into bundles)
_RE_PROCESS_ENV = re.compile(
    r'process\.env\.'
    r'([A-Z_][A-Z0-9_]{1,80})'
    r'\s*(?:\|\|)?\s*["\x27`]([^"\x27`]{1,512})["\x27`]',
    re.IGNORECASE,
)

# import.meta.env.VITE_API_URL (Vite - baked into bundles as literals)
_RE_IMPORT_META_ENV = re.compile(
    r'import\.meta\.env\.'
    r'([A-Z_][A-Z0-9_]{1,80})'
    r'(?:\s*\|\|\s*["\x27`]([^"\x27`]{0,512})["\x27`])?',
    re.IGNORECASE,
)

# API base URL patterns: apiBase, apiBaseUrl, baseURL, apiUrl, etc.
_RE_API_BASE = re.compile(
    r'["\x27`]?'
    r'(?:apiBase(?:Url)?|baseURL?|api(?:Url|Root|Host|Origin|Endpoint)|'
    r'serviceUrl|backendUrl|serverUrl|restBase|graphqlUrl|wsUrl)'
    r'["\x27`]?'
    r'\s*[=:]\s*'
    r'["\x27`]([^"\x27`\s]{4,512})["\x27`]',
    re.IGNORECASE,
)

# <meta name="api-base-url" content="..."> or data-api-url="..."
_RE_META_CONFIG = re.compile(
    r'<meta\s[^>]*?(?:name|property)\s*=\s*["\x27]'
    r'([^"\']{1,80})'
    r'["\x27]\s[^>]*?content\s*=\s*["\x27]'
    r'([^"\x27]{1,512})'
    r'["\x27]',
    re.IGNORECASE,
)

# data-config="{...}" embedded in script or div tags
_RE_DATA_CONFIG = re.compile(
    r'data-(?:config|settings|env|app-config)\s*=\s*["\x27](\{[^"\']{0,8000})["\x27]',
    re.IGNORECASE,
)

# Keys that suggest API/service configuration
_API_KEYS = frozenset({
    "api", "apiurl", "apibase", "apibaseurl", "baseurl", "baseuri",
    "apihost", "apiroot", "apiorigin", "apiendpoint", "serviceurl",
    "backendurl", "serverurl", "restbase", "graphqlurl", "wsurl",
    "endpoint", "endpoints", "host", "hosts", "origin",
    "publicurl", "siteurl", "appurl", "frontendurl",
})

_ENV_PREFIXES = frozenset({
    "REACT_APP_", "NEXT_PUBLIC_", "VITE_", "VUE_APP_", "GATSBY_",
    "NUXT_PUBLIC_", "PUBLIC_", "APP_",
})


@dataclass
class ConfigEntry:
    """One key-value pair extracted from a config global."""
    key:    str
    value:  str
    source: str   # which global/pattern this came from
    raw_context: str = ""  # short snippet for evidence


@dataclass
class BootConfig:
    """
    All configuration intelligence extracted from one asset (HTML or JS).

    api_bases  - resolved API base URL strings (most valuable for attack surface)
    env_vars   - raw env-var name/value pairs (process.env.X, import.meta.env.X)
    config_map - key/value pairs from structured config objects
    feature_flags - boolean or toggle values that look like feature flags
    raw_globals - names of config globals found (e.g. "__CONFIG__", "APP_CONFIG")
    """
    asset_url:     str
    api_bases:     List[str]       = field(default_factory=list)
    env_vars:      List[ConfigEntry] = field(default_factory=list)
    config_map:    List[ConfigEntry] = field(default_factory=list)
    feature_flags: List[ConfigEntry] = field(default_factory=list)
    raw_globals:   List[str]       = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.api_bases or self.env_vars or self.config_map or self.feature_flags)


def _looks_like_api_url(value: str) -> bool:
    """True if this string value looks like an API base URL or origin."""
    if not value or len(value) < 4:
        return False
    v = value.strip()
    if v.startswith(("http://", "https://", "//", "/")):
        return True
    # Relative paths that look like API prefixes
    if re.match(r'^/[a-z][a-z0-9_\-/]{1,40}$', v, re.IGNORECASE):
        return True
    return False


def _looks_like_flag(key: str, value: str) -> bool:
    """True if this looks like a feature flag rather than a URL/credential."""
    vl = str(value).lower()
    return vl in ("true", "false", "1", "0", "on", "off", "yes", "no", "enabled", "disabled")


def _extract_json_object(text: str, start: int) -> Optional[str]:
    """
    Extract a balanced JSON object starting from 'start' (which should point at '{').
    Returns the raw JSON string or None if balancing fails.
    """
    if start >= len(text) or text[start] != "{":
        return None
    depth = 0
    in_str = False
    escape = False
    end = start
    for i, ch in enumerate(text[start:], start):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_str:
            escape = True
            continue
        if ch == '"' and not escape:
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if depth != 0:
        return None
    return text[start:end + 1]


def _flatten_config(obj: Any, prefix: str, out: List[ConfigEntry], source: str, _depth: int = 0) -> None:
    """Flatten a nested config dict into ConfigEntry list."""
    if _depth > 6 or not isinstance(obj, dict):
        return
    for k, v in obj.items():
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            _flatten_config(v, full_key, out, source, _depth + 1)
        elif isinstance(v, (str, int, float, bool)):
            out.append(ConfigEntry(key=full_key, value=str(v), source=source))


def extract_boot_config(content: str, asset_url: str) -> BootConfig:
    """
    Extract boot-time configuration from HTML or JS content.

    No network I/O. Works on already-collected content only.
    """
    result = BootConfig(asset_url=asset_url)

    # ── 1. Structured config globals (window.__CONFIG__ = {...}) ─────────────
    for m in _RE_CONFIG_GLOBALS.finditer(content):
        global_name = m.group(1)
        raw_val     = m.group(2).strip()
        obj_raw     = _extract_json_object(raw_val, 0)
        if not obj_raw:
            continue
        try:
            obj = json.loads(obj_raw)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        result.raw_globals.append(global_name)
        entries: List[ConfigEntry] = []
        _flatten_config(obj, "", entries, global_name)
        for entry in entries:
            if _looks_like_flag(entry.key, entry.value):
                result.feature_flags.append(entry)
            elif _looks_like_api_url(entry.value):
                result.api_bases.append(entry.value)
                result.config_map.append(entry)
            else:
                result.config_map.append(entry)

    # ── 2. Module-level config vars (const CONFIG = {...}) ───────────────────
    for m in _RE_MODULE_CONFIG.finditer(content):
        global_name = m.group(1)
        raw_val     = m.group(2).strip()
        obj_raw     = _extract_json_object(raw_val, 0)
        if not obj_raw:
            continue
        try:
            obj = json.loads(obj_raw)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        if global_name not in result.raw_globals:
            result.raw_globals.append(global_name)
        entries = []
        _flatten_config(obj, "", entries, global_name)
        for entry in entries:
            if _looks_like_flag(entry.key, entry.value):
                result.feature_flags.append(entry)
            elif _looks_like_api_url(entry.value):
                result.api_bases.append(entry.value)
                result.config_map.append(entry)
            else:
                result.config_map.append(entry)

    # ── 3. Individual property assignments (window.env.API_URL = "...") ──────
    for m in _RE_ENV_PROP.finditer(content):
        key, value = m.group(1), m.group(2)
        entry = ConfigEntry(key=key, value=value, source="window.env")
        if _looks_like_flag(key, value):
            result.feature_flags.append(entry)
        elif _looks_like_api_url(value):
            result.api_bases.append(value)
            result.env_vars.append(entry)
        else:
            result.env_vars.append(entry)

    # ── 4. process.env baked-in values (CRA / Next.js bundles) ──────────────
    for m in _RE_PROCESS_ENV.finditer(content):
        key, value = m.group(1), m.group(2)
        # Only care about API-relevant env vars
        key_upper = key.upper()
        is_relevant = any(key_upper.startswith(p) for p in _ENV_PREFIXES)
        is_relevant = is_relevant or any(k in key_upper.lower() for k in ("url", "host", "api", "base", "endpoint"))
        if not is_relevant:
            continue
        entry = ConfigEntry(key=key, value=value, source="process.env")
        if _looks_like_api_url(value):
            result.api_bases.append(value)
        result.env_vars.append(entry)

    # ── 5. import.meta.env (Vite) ────────────────────────────────────────────
    for m in _RE_IMPORT_META_ENV.finditer(content):
        key     = m.group(1)
        value   = m.group(2) or ""
        key_upper = key.upper()
        if not any(k in key_upper.lower() for k in ("url", "host", "api", "base", "endpoint", "key", "token")):
            continue
        entry = ConfigEntry(key=key, value=value, source="import.meta.env")
        if value and _looks_like_api_url(value):
            result.api_bases.append(value)
        result.env_vars.append(entry)

    # ── 6. Inline API base URL strings ───────────────────────────────────────
    for m in _RE_API_BASE.finditer(content):
        value = m.group(1)
        if _looks_like_api_url(value) and value not in result.api_bases:
            result.api_bases.append(value)

    # ── 7. HTML <meta> config tags ───────────────────────────────────────────
    for m in _RE_META_CONFIG.finditer(content):
        name, value = m.group(1).lower(), m.group(2)
        if any(k in name for k in ("api", "config", "base", "url", "endpoint", "host")):
            entry = ConfigEntry(key=name, value=value, source="<meta>")
            result.config_map.append(entry)
            if _looks_like_api_url(value):
                result.api_bases.append(value)

    # ── 8. data-config="{...}" attributes ────────────────────────────────────
    for m in _RE_DATA_CONFIG.finditer(content):
        raw = m.group(1)
        # Repair the closing brace that was eaten by the lookahead
        obj_raw = _extract_json_object(raw + "}", 0) or _extract_json_object(raw, 0)
        if not obj_raw:
            continue
        try:
            obj = json.loads(obj_raw)
        except Exception:
            continue
        if isinstance(obj, dict):
            entries = []
            _flatten_config(obj, "", entries, "data-config")
            for entry in entries:
                if _looks_like_api_url(entry.value):
                    result.api_bases.append(entry.value)
                    result.config_map.append(entry)
                elif _looks_like_flag(entry.key, entry.value):
                    result.feature_flags.append(entry)
                else:
                    result.config_map.append(entry)

    # Deduplicate api_bases
    seen: Set[str] = set()
    deduped = []
    for base in result.api_bases:
        norm = base.rstrip("/").lower()
        if norm not in seen:
            seen.add(norm)
            deduped.append(base)
    result.api_bases = deduped

    if not result.is_empty():
        logger.debug(
            "boot_config: %s - globals=%s api_bases=%d env_vars=%d flags=%d",
            asset_url.split("/")[-1] or asset_url,
            result.raw_globals,
            len(result.api_bases),
            len(result.env_vars),
            len(result.feature_flags),
        )

    return result


def summarize_boot_configs(configs: List[BootConfig]) -> Dict[str, Any]:
    """
    Merge boot config results from all assets into a single summary dict.
    Used for final report output.
    """
    all_bases:    List[str]         = []
    all_env:      List[ConfigEntry] = []
    all_config:   List[ConfigEntry] = []
    all_flags:    List[ConfigEntry] = []
    all_globals:  List[str]         = []

    seen_bases:  Set[str] = set()
    seen_envkeys: Set[str] = set()

    for cfg in configs:
        for b in cfg.api_bases:
            norm = b.rstrip("/").lower()
            if norm not in seen_bases:
                seen_bases.add(norm)
                all_bases.append(b)
        for e in cfg.env_vars:
            if e.key not in seen_envkeys:
                seen_envkeys.add(e.key)
                all_env.append(e)
        all_config.extend(cfg.config_map)
        all_flags.extend(cfg.feature_flags)
        for g in cfg.raw_globals:
            if g not in all_globals:
                all_globals.append(g)

    return {
        "api_bases":     all_bases,
        "env_vars":      [{"key": e.key, "value": e.value, "source": e.source} for e in all_env],
        "config_entries": [{"key": e.key, "value": e.value, "source": e.source} for e in all_config],
        "feature_flags": [{"key": e.key, "value": e.value, "source": e.source} for e in all_flags],
        "globals_found": all_globals,
    }

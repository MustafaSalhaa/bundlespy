"""
Canonical discovery registry for BundleSpy.

Provides typed, distinct lanes for every kind of object the scanner
produces. Nothing is rewritten - existing Endpoint, Finding, JSFile,
and InfrastructureItem dataclasses are unchanged. The registry is a
structured container that enforces lane separation, prevents accidental
mixing, and tracks provenance.

Lanes:
    routes          - frontend page routes (Endpoint with category=ROUTE)
    endpoints       - API / WS / GraphQL / auth endpoints (Endpoint, non-ROUTE)
    findings        - secret / credential findings (Finding)
    assets          - JS files and source maps (JSFile)
    runtime_events  - runtime-intercepted events (dict-based, flexible shape)

Cross-lane correlation is preserved: the same URL may appear as a ROUTE
and as an API endpoint; correlate() returns a mapping of URL -> list of
typed records across all relevant lanes.

Usage:

    from bundlespy.storage.registry import DiscoveryRegistry

    reg = DiscoveryRegistry()
    reg.add(endpoint)   # auto-routed to routes or endpoints lane
    reg.add(finding)
    reg.add(js_file)

    routes    = reg.routes
    endpoints = reg.endpoints
    all_eps   = reg.all_endpoints   # routes + endpoints combined

    corr = reg.correlate("/admin")  # everything touching /admin
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from .models import Endpoint, Finding, JSFile, InfrastructureItem


@dataclass
class DiscoveryRegistry:
    """
    Typed container for all discovery output, split into five lanes.

    Deduplication is per-lane:
        - routes and endpoints: by lowercased url (stripped of trailing slash
          and query string), same rule as _add_ep() in cli.py
        - findings: by Finding.sha256
        - assets: by JSFile.sha256 (or url when sha256 is absent)
        - runtime_events: by (event_type, url) tuple

    The registry never raises on add(); bad objects are silently ignored.
    """

    _routes:         List[Endpoint]           = field(default_factory=list)
    _endpoints:      List[Endpoint]           = field(default_factory=list)
    _findings:       List[Finding]            = field(default_factory=list)
    _assets:         List[JSFile]             = field(default_factory=list)
    _infra:          List[InfrastructureItem] = field(default_factory=list)
    _runtime_events: List[dict]               = field(default_factory=list)

    _route_keys:   Set[str]   = field(default_factory=set)
    _ep_keys:      Set[str]   = field(default_factory=set)
    _find_keys:    Set[str]   = field(default_factory=set)
    _asset_keys:   Set[str]   = field(default_factory=set)
    _event_keys:   Set[tuple] = field(default_factory=set)

    @property
    def routes(self) -> List[Endpoint]:
        """Frontend page routes only (category=ROUTE)."""
        return list(self._routes)

    @property
    def endpoints(self) -> List[Endpoint]:
        """API / WS / GraphQL / auth endpoints (non-ROUTE)."""
        return list(self._endpoints)

    @property
    def all_endpoints(self) -> List[Endpoint]:
        """Routes + endpoints combined - matches the legacy flat list shape."""
        return list(self._routes) + list(self._endpoints)

    @property
    def findings(self) -> List[Finding]:
        return list(self._findings)

    @property
    def assets(self) -> List[JSFile]:
        return list(self._assets)

    @property
    def infrastructure(self) -> List[InfrastructureItem]:
        return list(self._infra)

    @property
    def runtime_events(self) -> List[dict]:
        return list(self._runtime_events)

    def add(self, obj: Any, source_type: str = "static") -> bool:
        """
        Add any discovery object to the correct lane.

        Returns True if the object was new, False if already present.
        Never raises.
        """
        try:
            if isinstance(obj, Endpoint):
                return self._add_endpoint(obj, source_type)
            if isinstance(obj, Finding):
                return self._add_finding(obj)
            if isinstance(obj, JSFile):
                return self._add_asset(obj)
            if isinstance(obj, InfrastructureItem):
                return self._add_infra(obj)
            if isinstance(obj, dict):
                return self._add_runtime_event(obj)
        except Exception:
            pass
        return False

    def add_route(self, ep: Endpoint, source_type: str = "static") -> bool:
        """Force-classify an endpoint as a frontend route."""
        try:
            ep.category = "ROUTE"
            return self._add_endpoint(ep, source_type)
        except Exception:
            return False

    def add_endpoint(self, ep: Endpoint, source_type: str = "static") -> bool:
        """Explicitly add to the endpoints lane (non-ROUTE)."""
        try:
            return self._add_endpoint(ep, source_type)
        except Exception:
            return False

    def add_runtime_event(self, event_type: str, url: str,
                          method: str = "GET", extra: dict = None) -> bool:
        """Add a runtime-intercepted network event."""
        return self._add_runtime_event({
            "event_type": event_type,
            "url": url,
            "method": method,
            **(extra or {}),
        })

    @staticmethod
    def _ep_key(ep: Endpoint) -> str:
        return ep.url.rstrip("/").lower().split("?")[0]

    def _add_endpoint(self, ep: Endpoint, source_type: str) -> bool:
        try:
            ep.source_type = source_type
        except Exception:
            pass
        key = self._ep_key(ep)
        is_route = ep.category == "ROUTE"
        if is_route:
            if key in self._route_keys:
                return False
            self._route_keys.add(key)
            self._routes.append(ep)
        else:
            if key in self._ep_keys:
                return False
            self._ep_keys.add(key)
            self._endpoints.append(ep)
        return True

    def _add_finding(self, f: Finding) -> bool:
        if f.sha256 in self._find_keys:
            return False
        self._find_keys.add(f.sha256)
        self._findings.append(f)
        return True

    def _add_asset(self, js: JSFile) -> bool:
        key = js.sha256 or js.url
        if key in self._asset_keys:
            return False
        self._asset_keys.add(key)
        self._assets.append(js)
        return True

    def _add_infra(self, item: InfrastructureItem) -> bool:
        key = (item.value.lower(), item.classification)
        if key in self._event_keys:
            return False
        self._event_keys.add(key)
        self._infra.append(item)
        return True

    def _add_runtime_event(self, event: dict) -> bool:
        key = (event.get("event_type", ""), event.get("url", ""))
        if key in self._event_keys:
            return False
        self._event_keys.add(key)
        self._runtime_events.append(event)
        return True

    def correlate(self, url: str) -> Dict[str, list]:
        """
        Return all registry entries that reference a given URL, grouped by lane.
        Prefix match - correlate("/admin") also finds "/admin/users".
        """
        norm = url.rstrip("/").lower().split("?")[0]

        def _ep_match(ep: Endpoint) -> bool:
            ep_norm = ep.url.rstrip("/").lower().split("?")[0]
            return ep_norm == norm or ep_norm.startswith(norm + "/")

        def _find_match(f: Finding) -> bool:
            return norm in f.file_url.lower() or norm in f.context.lower()

        def _asset_match(js: JSFile) -> bool:
            return norm in js.url.lower() or norm in js.source_page.lower()

        def _event_match(ev: dict) -> bool:
            return norm in ev.get("url", "").lower()

        return {
            "routes":         [ep for ep in self._routes    if _ep_match(ep)],
            "endpoints":      [ep for ep in self._endpoints if _ep_match(ep)],
            "findings":       [f  for f  in self._findings  if _find_match(f)],
            "assets":         [js for js in self._assets    if _asset_match(js)],
            "runtime_events": [ev for ev in self._runtime_events if _event_match(ev)],
        }

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "routes":         len(self._routes),
            "endpoints":      len(self._endpoints),
            "findings":       len(self._findings),
            "assets":         len(self._assets),
            "infrastructure": len(self._infra),
            "runtime_events": len(self._runtime_events),
        }

    def __repr__(self) -> str:
        s = self.stats
        return (
            f"DiscoveryRegistry("
            f"routes={s['routes']}, "
            f"endpoints={s['endpoints']}, "
            f"findings={s['findings']}, "
            f"assets={s['assets']}, "
            f"infra={s['infrastructure']}, "
            f"runtime={s['runtime_events']})"
        )

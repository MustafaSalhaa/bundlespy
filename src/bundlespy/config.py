"""
Central configuration for BundleSpy.
All defaults live here. CLI args and YAML configs override these.
"""

from dataclasses import dataclass, field
from typing import List, Optional

PROJECT_NAME    = "BundleSpy"
PROJECT_VERSION = "1.0.0"
AUTHOR_NAME     = "Mustafa Salha"
GITHUB_URL      = "https://github.com/MustafaSalhaa/bundlespy"
USER_AGENT      = f"{PROJECT_NAME}/{PROJECT_VERSION} (authorized security assessment)"

@dataclass
class ScopeConfig:
    same_origin: bool = True
    subdomains: bool  = False
    exclude: List[str] = field(default_factory=list)

@dataclass
class CrawlerConfig:
    depth: int               = 2
    max_pages: int           = 100
    max_js_files: int        = 200
    concurrency: int         = 4
    requests_per_second: int = 2
    timeout: int             = 10
    max_redirects: int       = 5
    max_response_size: int   = 10 * 1024 * 1024  # 10 MB
    retry_limit: int         = 2
    respect_robots: bool     = True

@dataclass
class DiscoveryConfig:
    common_paths: bool  = False
    source_maps: bool   = False

@dataclass
class AnalysisConfig:
    secrets: bool        = True
    endpoints: bool      = True
    infrastructure: bool = True
    cloud: bool          = True
    jwt_analysis: bool   = True

@dataclass
class AIConfig:
    enabled: bool   = False
    provider: str   = "disabled"
    model: str      = ""
    api_key: str    = ""

@dataclass
class ReportingConfig:
    formats: List[str]    = field(default_factory=lambda: ["terminal"])
    output_dir: str       = "./bundlespy-reports"
    show_sensitive: bool  = False

@dataclass
class SafetyConfig:
    block_private_networks: bool = True
    block_loopback: bool         = True
    block_link_local: bool       = True
    require_authorization: bool  = True

@dataclass
class PolicyConfig:
    fail_on_severity: str   = "critical"
    minimum_confidence: float = 0.70
    allow_rules: List[str]  = field(default_factory=list)

@dataclass
class BundleSpyConfig:
    target_url: str              = ""
    scope: ScopeConfig           = field(default_factory=ScopeConfig)
    crawler: CrawlerConfig       = field(default_factory=CrawlerConfig)
    discovery: DiscoveryConfig   = field(default_factory=DiscoveryConfig)
    analysis: AnalysisConfig     = field(default_factory=AnalysisConfig)
    ai: AIConfig                 = field(default_factory=AIConfig)
    reporting: ReportingConfig   = field(default_factory=ReportingConfig)
    safety: SafetyConfig         = field(default_factory=SafetyConfig)
    policy: PolicyConfig         = field(default_factory=PolicyConfig)
    verbose: bool                = False
    quiet: bool                  = False
    no_color: bool               = False

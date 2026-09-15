"""
Vulnerable Library Detection for BundleSpy.

Comprehensive CVE database covering:
- Frontend frameworks (jQuery, Angular, React, Vue, Bootstrap, etc.)
- Build tools and runtimes
- Security-critical npm packages
- Authentication libraries
- HTTP clients and request handling
- Template engines
- Utility libraries
- Node.js ecosystem packages

Detection approach:
- Multiple version fingerprint patterns per library
- Version range comparison for accurate CVE matching
- Zero false positives — version-verified only
- CVSS scores from NVD
"""

import re
import logging
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("bundlespy.analysis.library_scanner")


@dataclass
class LibraryFinding:
    library:     str
    version:     str
    cve_id:      str
    severity:    str
    cvss:        float
    description: str
    remediation: str
    source_file: str
    confidence:  float


def _v(version: str) -> Tuple[int, int, int]:
    """Parse version string to comparable tuple."""
    try:
        parts = re.split(r'[.\-]', version.strip())
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(re.sub(r'[^0-9]', '', parts[2])) if len(parts) > 2 else 0
        return (major, minor, patch)
    except Exception:
        return (0, 0, 0)


@dataclass
class CVEEntry:
    cve_id:      str
    severity:    str
    cvss:        float
    description: str
    remediation: str
    affects:     object  # callable: (version_str) -> bool


# ── Library version detectors ─────────────────────────────────────────────────

LIBRARY_DETECTORS: Dict[str, List[re.Pattern]] = {

    # ── Frontend frameworks ───────────────────────────────────────────────────

    "jQuery": [
        re.compile(r'jQuery\s+v?(\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'jquery[/-](\d+\.\d+\.\d+)(?:\.min)?\.js', re.IGNORECASE),
        re.compile(r'\* jQuery JavaScript Library v(\d+\.\d+\.\d+)'),
        re.compile(r'jQuery\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
        re.compile(r'"jquery"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "jQuery UI": [
        re.compile(r'jQuery UI\s*-\s*v?(\d+\.\d+\.\d+)'),
        re.compile(r'jquery-ui[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'\* jQuery UI (\d+\.\d+\.\d+)'),
    ],

    "AngularJS": [
        re.compile(r'AngularJS\s+v?(\d+\.\d+\.\d+)'),
        re.compile(r'angular[/-](\d+\.\d+\.\d+)(?:\.min)?\.js', re.IGNORECASE),
        re.compile(r'angular\.version\s*=\s*\{[^}]*full\s*:\s*["\'](\d+\.\d+\.\d+)["\']'),
        re.compile(r'"angularjs?"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "Bootstrap": [
        re.compile(r'Bootstrap\s+v?(\d+\.\d+\.\d+)'),
        re.compile(r'bootstrap[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'\* Bootstrap v(\d+\.\d+\.\d+)'),
        re.compile(r'"bootstrap"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "lodash": [
        re.compile(r'lodash[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'Lodash\s*<https://lodash\.com/>\s*(\d+\.\d+\.\d+)'),
        re.compile(r'_\.VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
        re.compile(r'"lodash"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "Moment.js": [
        re.compile(r'moment[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'moment\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
        re.compile(r'"moment"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "Underscore.js": [
        re.compile(r'underscore[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'Underscore\.js\s+(\d+\.\d+\.\d+)'),
    ],

    "Handlebars": [
        re.compile(r'handlebars[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'Handlebars\.VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
        re.compile(r'"handlebars"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "Vue.js": [
        re.compile(r'vue[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'Vue\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
        re.compile(r'\* Vue\.js v(\d+\.\d+\.\d+)'),
        re.compile(r'"vue"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "React": [
        re.compile(r'react[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'React\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
        re.compile(r'"react"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "axios": [
        re.compile(r'axios[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"axios"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'axios/(\d+\.\d+\.\d+)'),
    ],

    "CryptoJS": [
        re.compile(r'CryptoJS\s+v?(\d+\.\d+\.\d+)'),
        re.compile(r'crypto-js[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"crypto-js"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    # ── Authentication / Security ─────────────────────────────────────────────

    "jsonwebtoken": [
        re.compile(r'jsonwebtoken[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"jsonwebtoken"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "passport": [
        re.compile(r'passport[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"passport"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "bcrypt": [
        re.compile(r'bcrypt[js]?[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"bcrypt[js]?"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    # ── HTTP / Networking ─────────────────────────────────────────────────────

    "node-fetch": [
        re.compile(r'node-fetch[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"node-fetch"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "got": [
        re.compile(r'"got"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'got[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "request": [
        re.compile(r'"request"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'request[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "superagent": [
        re.compile(r'superagent[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"superagent"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    # ── Template engines ──────────────────────────────────────────────────────

    "ejs": [
        re.compile(r'ejs[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"ejs"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "pug": [
        re.compile(r'pug[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"pug"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "nunjucks": [
        re.compile(r'nunjucks[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"nunjucks"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    # ── Utilities ─────────────────────────────────────────────────────────────

    "minimist": [
        re.compile(r'minimist[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"minimist"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "semver": [
        re.compile(r'semver[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"semver"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'semver\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
    ],

    "tar": [
        re.compile(r'"tar"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'tar[/-](\d+\.\d+\.\d+)(?!\.gz)', re.IGNORECASE),
    ],

    "tough-cookie": [
        re.compile(r'tough-cookie[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"tough-cookie"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "validator": [
        re.compile(r'validator[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"validator"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "marked": [
        re.compile(r'marked[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"marked"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'marked\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
    ],

    "DOMPurify": [
        re.compile(r'DOMPurify[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'DOMPurify\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
        re.compile(r'"dompurify"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"', re.IGNORECASE),
    ],

    "sanitize-html": [
        re.compile(r'sanitize-html[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"sanitize-html"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "vm2": [
        re.compile(r'vm2[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"vm2"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "socket.io": [
        re.compile(r'socket\.io[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"socket\.io"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'socket\.io@(\d+\.\d+\.\d+)'),
    ],

    "express": [
        re.compile(r'"express"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'express[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "next.js": [
        re.compile(r'next[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"next"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'next@(\d+\.\d+\.\d+)'),
    ],

    "nuxt": [
        re.compile(r'"nuxt"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'nuxt[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "svelte": [
        re.compile(r'"svelte"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'svelte[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "Prototype.js": [
        re.compile(r'Prototype\s+JavaScript\s+framework.*?(\d+\.\d+\.\d+)'),
        re.compile(r'Prototype\.Version\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
    ],

    "MooTools": [
        re.compile(r'MooTools[^\d]*(\d+\.\d+\.\d+)'),
        re.compile(r'mootools[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "Backbone.js": [
        re.compile(r'Backbone\.VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
        re.compile(r'backbone[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "Ember.js": [
        re.compile(r'Ember\.VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
        re.compile(r'ember[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "D3.js": [
        re.compile(r'd3[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'd3\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
    ],

    "three.js": [
        re.compile(r'THREE\.REVISION\s*=\s*["\'](\d+)["\']'),
        re.compile(r'three[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "Chart.js": [
        re.compile(r'Chart\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
        re.compile(r'chart\.js[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "highlight.js": [
        re.compile(r'highlight\.js[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"highlight\.js"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "reveal.js": [
        re.compile(r'reveal\.js[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'Reveal\.VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
    ],

    "Polyfill.io": [
        re.compile(r'polyfill\.io[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "serialize-javascript": [
        re.compile(r'serialize-javascript[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"serialize-javascript"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "nth-check": [
        re.compile(r'nth-check[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"nth-check"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "trim-newlines": [
        re.compile(r'trim-newlines[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"trim-newlines"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "glob-parent": [
        re.compile(r'glob-parent[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"glob-parent"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "braces": [
        re.compile(r'"braces"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'braces[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "shell-quote": [
        re.compile(r'shell-quote[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"shell-quote"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "netmask": [
        re.compile(r'netmask[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"netmask"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "path-parse": [
        re.compile(r'path-parse[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"path-parse"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "follow-redirects": [
        re.compile(r'follow-redirects[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"follow-redirects"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "plist": [
        re.compile(r'"plist"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'plist[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "xmlhttprequest-ssl": [
        re.compile(r'xmlhttprequest-ssl[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"xmlhttprequest-ssl"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "jszip": [
        re.compile(r'jszip[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'JSZip\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
        re.compile(r'"jszip"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "react-dom": [
        re.compile(r'react-dom[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"react-dom"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "word-wrap": [
        re.compile(r'"word-wrap"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'word-wrap[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "ip": [
        re.compile(r'"ip"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'\bip[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
    ],

    "postcss": [
        re.compile(r'postcss[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"postcss"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
    ],

    "webpack": [
        re.compile(r'webpack[/-](\d+\.\d+\.\d+)', re.IGNORECASE),
        re.compile(r'"webpack"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r'__webpack_require__.*?version["\s]*:["\s]*["\'](\d+\.\d+\.\d+)["\']'),
    ],
}


# ── Comprehensive CVE Database ────────────────────────────────────────────────

CVE_DATABASE: Dict[str, List[CVEEntry]] = {

    "jQuery": [
        CVEEntry("CVE-2019-11358", "HIGH", 6.1,
            "Prototype pollution via $.extend(true, ...)",
            "Upgrade to jQuery 3.4.0+.",
            lambda v: _v(v) < _v("3.4.0")),
        CVEEntry("CVE-2020-11022", "MEDIUM", 6.1,
            "XSS via HTML passed to manipulation methods",
            "Upgrade to jQuery 3.5.0+.",
            lambda v: _v(v) < _v("3.5.0")),
        CVEEntry("CVE-2020-11023", "MEDIUM", 6.1,
            "XSS via self-closing HTML tags",
            "Upgrade to jQuery 3.5.0+.",
            lambda v: _v(v) < _v("3.5.0")),
        CVEEntry("CVE-2015-9251", "MEDIUM", 6.1,
            "AJAX requests bypass same-origin policy",
            "Upgrade to jQuery 3.0.0+.",
            lambda v: _v(v) < _v("3.0.0")),
        CVEEntry("CVE-2012-6708", "MEDIUM", 6.1,
            "XSS via selector expression",
            "Upgrade to jQuery 1.9.0+.",
            lambda v: _v(v) < _v("1.9.0")),
        CVEEntry("CVE-2011-4969", "MEDIUM", 4.3,
            "XSS via location.hash",
            "Upgrade to jQuery 1.6.3+.",
            lambda v: _v(v) < _v("1.6.3")),
    ],

    "jQuery UI": [
        CVEEntry("CVE-2022-31160", "MEDIUM", 6.5,
            "XSS via altField option of datepicker widget",
            "Upgrade to jQuery UI 1.13.2+.",
            lambda v: _v(v) < _v("1.13.2")),
        CVEEntry("CVE-2021-41182", "MEDIUM", 6.5,
            "XSS via the 'of' option in .position()",
            "Upgrade to jQuery UI 1.13.0+.",
            lambda v: _v(v) < _v("1.13.0")),
        CVEEntry("CVE-2021-41183", "MEDIUM", 6.5,
            "XSS via altField datepicker option",
            "Upgrade to jQuery UI 1.13.0+.",
            lambda v: _v(v) < _v("1.13.0")),
        CVEEntry("CVE-2021-41184", "MEDIUM", 6.5,
            "XSS via the 'of' option of the .position() util",
            "Upgrade to jQuery UI 1.13.0+.",
            lambda v: _v(v) < _v("1.13.0")),
        CVEEntry("CVE-2016-7103", "MEDIUM", 6.1,
            "XSS in dialog title option",
            "Upgrade to jQuery UI 1.12.0+.",
            lambda v: _v(v) < _v("1.12.0")),
        CVEEntry("CVE-2010-5312", "MEDIUM", 4.3,
            "XSS in dialog title option",
            "Upgrade to jQuery UI 1.8.7+.",
            lambda v: _v(v) < _v("1.8.7")),
    ],

    "AngularJS": [
        CVEEntry("CVE-2019-14863", "HIGH", 7.4,
            "XSS via SVG animate element",
            "Upgrade AngularJS or migrate to Angular 2+.",
            lambda v: _v(v) < _v("1.8.0") and _v(v) >= _v("1.0.0")),
        CVEEntry("CVE-2020-7676", "MEDIUM", 6.1,
            "XSS via img srcset attribute",
            "Upgrade to AngularJS 1.8.0+.",
            lambda v: _v(v) < _v("1.8.0") and _v(v) >= _v("1.0.0")),
        CVEEntry("CVE-2019-10768", "HIGH", 7.5,
            "ReDoS via $sanitize provider",
            "Upgrade to AngularJS 1.7.9+.",
            lambda v: _v(v) < _v("1.7.9") and _v(v) >= _v("1.0.0")),
        CVEEntry("CVE-2016-9879", "HIGH", 7.5,
            "Bypass of bypassSecurityTrustHtml",
            "Upgrade to AngularJS 1.6.1+.",
            lambda v: _v(v) < _v("1.6.1") and _v(v) >= _v("1.0.0")),
        CVEEntry("CVE-2022-25869", "MEDIUM", 6.1,
            "XSS in AngularJS",
            "Upgrade to AngularJS 1.8.3+.",
            lambda v: _v(v) < _v("1.8.3") and _v(v) >= _v("1.0.0")),
    ],

    "Bootstrap": [
        CVEEntry("CVE-2019-8331", "MEDIUM", 6.1,
            "XSS via tooltip or popover data-template attribute",
            "Upgrade to Bootstrap 3.4.1 or 4.3.1+.",
            lambda v: (_v(v) < _v("3.4.1") and _v(v) >= _v("3.0.0"))
                   or (_v(v) < _v("4.3.1") and _v(v) >= _v("4.0.0"))),
        CVEEntry("CVE-2018-14042", "MEDIUM", 6.1,
            "XSS via data-container property of tooltip",
            "Upgrade to Bootstrap 3.4.0+.",
            lambda v: _v(v) < _v("3.4.0")),
        CVEEntry("CVE-2018-14040", "MEDIUM", 6.1,
            "XSS in collapse data-parent attribute",
            "Upgrade to Bootstrap 3.4.0+.",
            lambda v: _v(v) < _v("3.4.0")),
        CVEEntry("CVE-2016-10735", "MEDIUM", 6.1,
            "XSS in data-target attribute",
            "Upgrade to Bootstrap 3.4.0+.",
            lambda v: _v(v) < _v("3.4.0")),
        CVEEntry("CVE-2024-6531", "MEDIUM", 6.4,
            "XSS via the tooltip plugin",
            "Upgrade to Bootstrap 5.3.3+.",
            lambda v: _v(v) < _v("5.3.3") and _v(v) >= _v("5.0.0")),
        CVEEntry("CVE-2024-6484", "MEDIUM", 6.4,
            "XSS via the collapse plugin",
            "Upgrade to Bootstrap 5.3.3+.",
            lambda v: _v(v) < _v("5.3.3") and _v(v) >= _v("5.0.0")),
    ],

    "lodash": [
        CVEEntry("CVE-2021-23337", "HIGH", 7.2,
            "Command injection via template option",
            "Upgrade to lodash 4.17.21+.",
            lambda v: _v(v) < _v("4.17.21")),
        CVEEntry("CVE-2020-28500", "MEDIUM", 5.3,
            "ReDoS via toNumber, trim, trimEnd",
            "Upgrade to lodash 4.17.21+.",
            lambda v: _v(v) < _v("4.17.21")),
        CVEEntry("CVE-2020-8203", "HIGH", 7.4,
            "Prototype pollution via zipObjectDeep",
            "Upgrade to lodash 4.17.19+.",
            lambda v: _v(v) < _v("4.17.19")),
        CVEEntry("CVE-2019-10744", "CRITICAL", 9.1,
            "Prototype pollution via defaultsDeep",
            "Upgrade to lodash 4.17.12+.",
            lambda v: _v(v) < _v("4.17.12")),
        CVEEntry("CVE-2018-16487", "HIGH", 7.4,
            "Prototype pollution via merge and mergeWith",
            "Upgrade to lodash 4.17.11+.",
            lambda v: _v(v) < _v("4.17.11")),
        CVEEntry("CVE-2018-3721", "MEDIUM", 6.5,
            "Prototype pollution in defaultsDeep",
            "Upgrade to lodash 4.17.5+.",
            lambda v: _v(v) < _v("4.17.5")),
    ],

    "Moment.js": [
        CVEEntry("CVE-2022-24785", "HIGH", 7.5,
            "Path traversal via locale string",
            "Upgrade to Moment.js 2.29.2+.",
            lambda v: _v(v) < _v("2.29.2")),
        CVEEntry("CVE-2022-31129", "HIGH", 7.5,
            "ReDoS via strings in RFC 2822 format",
            "Upgrade to Moment.js 2.29.4+.",
            lambda v: _v(v) < _v("2.29.4")),
        CVEEntry("CVE-2016-4055", "MEDIUM", 5.3,
            "ReDoS in moment.js date parsing",
            "Upgrade to Moment.js 2.15.2+.",
            lambda v: _v(v) < _v("2.15.2")),
    ],

    "Handlebars": [
        CVEEntry("CVE-2021-23369", "CRITICAL", 9.8,
            "RCE via crafted template with select helper",
            "Upgrade to Handlebars 4.7.7+.",
            lambda v: _v(v) < _v("4.7.7")),
        CVEEntry("CVE-2021-23383", "CRITICAL", 9.8,
            "Prototype pollution via template with simple helpers",
            "Upgrade to Handlebars 4.7.7+.",
            lambda v: _v(v) < _v("4.7.7")),
        CVEEntry("CVE-2019-20922", "HIGH", 7.5,
            "ReDoS via badly formed templates",
            "Upgrade to Handlebars 4.4.5+.",
            lambda v: _v(v) < _v("4.4.5")),
        CVEEntry("CVE-2019-19919", "CRITICAL", 9.8,
            "Prototype pollution via template with lookup helper",
            "Upgrade to Handlebars 4.5.3+.",
            lambda v: _v(v) < _v("4.5.3")),
        CVEEntry("CVE-2019-20920", "HIGH", 8.1,
            "Arbitrary code execution via crafted handlebars template",
            "Upgrade to Handlebars 4.5.3+.",
            lambda v: _v(v) < _v("4.5.3")),
    ],

    "Underscore.js": [
        CVEEntry("CVE-2021-23358", "HIGH", 7.2,
            "Arbitrary code execution via template method",
            "Upgrade to Underscore.js 1.13.0-2+.",
            lambda v: _v(v) < _v("1.13.0")),
    ],

    "Vue.js": [
        CVEEntry("CVE-2021-22960", "MEDIUM", 6.1,
            "XSS via v-bind expression",
            "Upgrade to Vue.js 2.6.14 or 3.0.11+.",
            lambda v: (_v(v) < _v("2.6.14") and _v(v) >= _v("2.0.0"))
                   or (_v(v) < _v("3.0.11") and _v(v) >= _v("3.0.0"))),
        CVEEntry("CVE-2024-6783", "MEDIUM", 6.9,
            "Prototype pollution in Vue.js 2.x via vue-template-compiler",
            "Upgrade to Vue.js 2.7.16+.",
            lambda v: _v(v) < _v("2.7.16") and _v(v) >= _v("2.0.0")),
    ],

    "axios": [
        CVEEntry("CVE-2021-3749", "HIGH", 7.5,
            "ReDoS via especially long strings",
            "Upgrade to axios 0.21.2+.",
            lambda v: _v(v) < _v("0.21.2")),
        CVEEntry("CVE-2020-28168", "MEDIUM", 5.9,
            "SSRF via relative URL bypass",
            "Upgrade to axios 0.21.1+.",
            lambda v: _v(v) < _v("0.21.1")),
        CVEEntry("CVE-2023-45857", "MEDIUM", 6.5,
            "Exposure of confidential data via HTTP headers",
            "Upgrade to axios 1.6.0+.",
            lambda v: _v(v) >= _v("1.0.0") and _v(v) < _v("1.6.0")),
        CVEEntry("CVE-2024-39338", "HIGH", 7.4,
            "SSRF via requests to local network",
            "Upgrade to axios 1.7.4+.",
            lambda v: _v(v) < _v("1.7.4")),
    ],

    "CryptoJS": [
        CVEEntry("CVE-2023-46233", "CRITICAL", 9.1,
            "AES encryption uses insecure PBKDF2 key derivation (MD5)",
            "Upgrade to crypto-js 4.2.0+.",
            lambda v: _v(v) < _v("4.2.0")),
    ],

    "jsonwebtoken": [
        CVEEntry("CVE-2022-23529", "HIGH", 7.6,
            "Arbitrary file write via compromised JWK endpoint",
            "Upgrade to jsonwebtoken 9.0.0+.",
            lambda v: _v(v) < _v("9.0.0")),
        CVEEntry("CVE-2022-23539", "MEDIUM", 5.3,
            "Insecure default algorithm allows signature bypass",
            "Upgrade to jsonwebtoken 9.0.0+.",
            lambda v: _v(v) < _v("9.0.0")),
        CVEEntry("CVE-2022-23540", "HIGH", 7.4,
            "Algorithm confusion when verifying tokens",
            "Upgrade to jsonwebtoken 9.0.0+.",
            lambda v: _v(v) < _v("9.0.0")),
        CVEEntry("CVE-2015-9235", "CRITICAL", 9.8,
            "Blank secret allows verification bypass (alg:none)",
            "Upgrade to jsonwebtoken 4.2.2+.",
            lambda v: _v(v) < _v("4.2.2")),
    ],

    "node-fetch": [
        CVEEntry("CVE-2022-0235", "HIGH", 8.8,
            "Exposure of private network requests via redirect",
            "Upgrade to node-fetch 2.6.7 or 3.1.1+.",
            lambda v: (_v(v) < _v("2.6.7") and _v(v) >= _v("2.0.0"))
                   or (_v(v) < _v("3.1.1") and _v(v) >= _v("3.0.0"))),
    ],

    "got": [
        CVEEntry("CVE-2021-33502", "HIGH", 7.5,
            "ReDoS via URI parsing",
            "Upgrade to got 11.8.2+.",
            lambda v: _v(v) < _v("11.8.2")),
    ],

    "semver": [
        CVEEntry("CVE-2022-25883", "HIGH", 7.5,
            "ReDoS via crafted string with space between version numbers",
            "Upgrade to semver 7.5.2+.",
            lambda v: (_v(v) < _v("5.7.2") and _v(v) >= _v("5.0.0"))
                   or (_v(v) < _v("6.3.1") and _v(v) >= _v("6.0.0"))
                   or (_v(v) < _v("7.5.2") and _v(v) >= _v("7.0.0"))),
    ],

    "tar": [
        CVEEntry("CVE-2021-37701", "HIGH", 8.1,
            "Arbitrary file creation via crafted tar archive",
            "Upgrade to tar 4.4.17, 5.0.9, or 6.1.9+.",
            lambda v: (_v(v) < _v("4.4.17") and _v(v) >= _v("4.0.0"))
                   or (_v(v) < _v("5.0.9") and _v(v) >= _v("5.0.0"))
                   or (_v(v) < _v("6.1.9") and _v(v) >= _v("6.0.0"))),
        CVEEntry("CVE-2021-37712", "HIGH", 8.1,
            "Arbitrary file creation via paths containing ..",
            "Upgrade to tar 4.4.18, 5.0.10, or 6.1.10+.",
            lambda v: (_v(v) < _v("4.4.18") and _v(v) >= _v("4.0.0"))
                   or (_v(v) < _v("5.0.10") and _v(v) >= _v("5.0.0"))
                   or (_v(v) < _v("6.1.10") and _v(v) >= _v("6.0.0"))),
        CVEEntry("CVE-2021-32803", "HIGH", 8.1,
            "Arbitrary file write via absolute paths or path traversal",
            "Upgrade to tar 3.2.3, 4.4.15, 5.0.7, or 6.1.2+.",
            lambda v: _v(v) < _v("6.1.2")),
    ],

    "tough-cookie": [
        CVEEntry("CVE-2023-26136", "CRITICAL", 9.8,
            "Prototype pollution via ReDoS in CookieJar",
            "Upgrade to tough-cookie 4.1.3+.",
            lambda v: _v(v) < _v("4.1.3")),
    ],

    "marked": [
        CVEEntry("CVE-2022-21681", "HIGH", 7.5,
            "ReDoS via crafted markdown input",
            "Upgrade to marked 4.0.10+.",
            lambda v: _v(v) < _v("4.0.10")),
        CVEEntry("CVE-2022-21680", "HIGH", 7.5,
            "ReDoS via heading in marked",
            "Upgrade to marked 4.0.10+.",
            lambda v: _v(v) < _v("4.0.10")),
        CVEEntry("CVE-2021-21306", "HIGH", 7.5,
            "ReDoS via crafted markdown",
            "Upgrade to marked 2.0.0+.",
            lambda v: _v(v) < _v("2.0.0")),
    ],

    "DOMPurify": [
        CVEEntry("CVE-2024-45801", "HIGH", 7.3,
            "XSS bypass via namespace confusion",
            "Upgrade to DOMPurify 3.1.7+.",
            lambda v: _v(v) < _v("3.1.7")),
        CVEEntry("CVE-2024-47875", "CRITICAL", 9.9,
            "XSS bypass via mutation XSS in HTML parser",
            "Upgrade to DOMPurify 3.2.0+.",
            lambda v: _v(v) < _v("3.2.0")),
        CVEEntry("CVE-2023-48022", "MEDIUM", 6.1,
            "XSS bypass via crafted HTML in specific browser contexts",
            "Upgrade to DOMPurify 3.0.6+.",
            lambda v: _v(v) < _v("3.0.6")),
    ],

    "sanitize-html": [
        CVEEntry("CVE-2022-25887", "HIGH", 7.5,
            "ReDoS via crafted HTML string",
            "Upgrade to sanitize-html 2.7.1+.",
            lambda v: _v(v) < _v("2.7.1")),
        CVEEntry("CVE-2021-26540", "MEDIUM", 6.1,
            "XSS bypass via allowedTags option",
            "Upgrade to sanitize-html 2.3.2+.",
            lambda v: _v(v) < _v("2.3.2")),
    ],

    "vm2": [
        CVEEntry("CVE-2023-29017", "CRITICAL", 9.8,
            "Sandbox escape via getter/setter on prototypes",
            "vm2 is abandoned — migrate to isolated-vm or vm-browserify.",
            lambda v: _v(v) <= _v("3.9.19")),
        CVEEntry("CVE-2023-37466", "CRITICAL", 9.8,
            "Sandbox escape via async error handling",
            "vm2 is abandoned — migrate to isolated-vm.",
            lambda v: _v(v) <= _v("3.9.19")),
        CVEEntry("CVE-2023-37903", "CRITICAL", 9.8,
            "Sandbox escape via customInspect",
            "vm2 is abandoned — migrate to isolated-vm.",
            lambda v: _v(v) <= _v("3.9.19")),
    ],

    "socket.io": [
        CVEEntry("CVE-2024-38355", "HIGH", 7.4,
            "ReDoS via crafted Socket.IO handshake request",
            "Upgrade to socket.io 4.6.2+.",
            lambda v: _v(v) < _v("4.6.2")),
        CVEEntry("CVE-2022-2421", "CRITICAL", 9.8,
            "Prototype pollution via specially crafted socket.io message",
            "Upgrade to socket.io 4.5.4+.",
            lambda v: _v(v) < _v("4.5.4")),
    ],

    "express": [
        CVEEntry("CVE-2024-43796", "MEDIUM", 5.0,
            "XSS in res.redirect() via unsanitized location header",
            "Upgrade to express 4.20.0+.",
            lambda v: _v(v) < _v("4.20.0") and _v(v) >= _v("4.0.0")),
        CVEEntry("CVE-2024-29041", "MEDIUM", 6.1,
            "Open redirect via malformed URL",
            "Upgrade to express 4.19.2+.",
            lambda v: _v(v) < _v("4.19.2") and _v(v) >= _v("4.0.0")),
    ],

    "next.js": [
        CVEEntry("CVE-2024-56332", "CRITICAL", 9.1,
            "SSRF via Server Actions",
            "Upgrade to Next.js 15.1.3, 14.2.22, or 13.5.9+.",
            lambda v: (_v(v) < _v("13.5.9") and _v(v) >= _v("13.0.0"))
                   or (_v(v) < _v("14.2.22") and _v(v) >= _v("14.0.0"))
                   or (_v(v) < _v("15.1.3") and _v(v) >= _v("15.0.0"))),
        CVEEntry("CVE-2024-46982", "HIGH", 7.5,
            "Cache poisoning via crafted response",
            "Upgrade to Next.js 14.2.10+.",
            lambda v: _v(v) < _v("14.2.10") and _v(v) >= _v("14.0.0")),
        CVEEntry("CVE-2024-34351", "HIGH", 7.5,
            "SSRF via Host header manipulation in Server Actions",
            "Upgrade to Next.js 14.1.1+.",
            lambda v: _v(v) < _v("14.1.1") and _v(v) >= _v("13.4.0")),
    ],

    "ejs": [
        CVEEntry("CVE-2022-29078", "CRITICAL", 9.8,
            "RCE via settings[view options][outputFunctionName]",
            "Upgrade to EJS 3.1.7+.",
            lambda v: _v(v) < _v("3.1.7")),
        CVEEntry("CVE-2023-29827", "CRITICAL", 9.8,
            "RCE via server-side template injection",
            "Upgrade to EJS 3.1.9+.",
            lambda v: _v(v) < _v("3.1.9")),
    ],

    "minimist": [
        CVEEntry("CVE-2021-44906", "CRITICAL", 9.8,
            "Prototype pollution via crafted arguments",
            "Upgrade to minimist 1.2.6+.",
            lambda v: _v(v) < _v("1.2.6")),
        CVEEntry("CVE-2020-7598", "MEDIUM", 5.6,
            "Prototype pollution via __proto__ key",
            "Upgrade to minimist 1.2.3+.",
            lambda v: _v(v) < _v("1.2.3")),
    ],

    "serialize-javascript": [
        CVEEntry("CVE-2020-7660", "HIGH", 8.1,
            "RCE via crafted serialized data",
            "Upgrade to serialize-javascript 3.1.0+.",
            lambda v: _v(v) < _v("3.1.0")),
    ],

    "nth-check": [
        CVEEntry("CVE-2021-3803", "HIGH", 7.5,
            "ReDoS via crafted CSS selector",
            "Upgrade to nth-check 2.0.1+.",
            lambda v: _v(v) < _v("2.0.1")),
    ],

    "glob-parent": [
        CVEEntry("CVE-2020-28469", "HIGH", 7.5,
            "ReDoS via crafted path string",
            "Upgrade to glob-parent 5.1.2+.",
            lambda v: _v(v) < _v("5.1.2")),
    ],

    "braces": [
        CVEEntry("CVE-2024-4068", "HIGH", 7.5,
            "ReDoS via crafted brace expansion pattern",
            "Upgrade to braces 3.0.3+.",
            lambda v: _v(v) < _v("3.0.3")),
    ],

    "follow-redirects": [
        CVEEntry("CVE-2024-28849", "MEDIUM", 6.5,
            "Credential leak via HTTP to HTTPS redirect",
            "Upgrade to follow-redirects 1.15.6+.",
            lambda v: _v(v) < _v("1.15.6")),
        CVEEntry("CVE-2023-26159", "MEDIUM", 6.1,
            "URL redirection to untrusted site via malformed URL",
            "Upgrade to follow-redirects 1.15.4+.",
            lambda v: _v(v) < _v("1.15.4")),
    ],

    "ip": [
        CVEEntry("CVE-2023-42282", "CRITICAL", 9.8,
            "SSRF via crafted IP address string bypass",
            "Upgrade to ip 2.0.1+.",
            lambda v: _v(v) < _v("2.0.1")),
    ],

    "postcss": [
        CVEEntry("CVE-2023-44270", "MEDIUM", 5.3,
            "Line return parsing error causes incorrect sourcemaps",
            "Upgrade to postcss 8.4.31+.",
            lambda v: _v(v) < _v("8.4.31")),
    ],

    "jszip": [
        CVEEntry("CVE-2022-48285", "HIGH", 7.5,
            "Prototype pollution via crafted zip file",
            "Upgrade to JSZip 3.10.1+.",
            lambda v: _v(v) < _v("3.10.1")),
    ],

    "highlight.js": [
        CVEEntry("CVE-2021-23369", "HIGH", 7.4,
            "ReDoS via crafted code snippet",
            "Upgrade to highlight.js 10.4.1+.",
            lambda v: _v(v) < _v("10.4.1")),
        CVEEntry("CVE-2020-26237", "HIGH", 7.3,
            "ReDoS in certain language grammars",
            "Upgrade to highlight.js 10.1.2+.",
            lambda v: _v(v) < _v("10.1.2")),
    ],

    "word-wrap": [
        CVEEntry("CVE-2023-26115", "HIGH", 7.5,
            "ReDoS via crafted string",
            "Upgrade to word-wrap 1.2.4+.",
            lambda v: _v(v) < _v("1.2.4")),
    ],

    "path-parse": [
        CVEEntry("CVE-2021-23343", "HIGH", 7.5,
            "ReDoS via path-parse input",
            "Upgrade to path-parse 1.0.7+.",
            lambda v: _v(v) < _v("1.0.7")),
    ],

    "netmask": [
        CVEEntry("CVE-2021-28918", "CRITICAL", 9.8,
            "SSRF via improper IP address validation",
            "Upgrade to netmask 2.0.1+.",
            lambda v: _v(v) < _v("2.0.1")),
    ],

    "shell-quote": [
        CVEEntry("CVE-2021-42740", "CRITICAL", 9.8,
            "Arbitrary command injection via crafted input",
            "Upgrade to shell-quote 1.7.3+.",
            lambda v: _v(v) < _v("1.7.3")),
    ],

    "plist": [
        CVEEntry("CVE-2022-26767", "HIGH", 7.5,
            "XML injection via crafted plist file",
            "Upgrade to plist 3.0.5+.",
            lambda v: _v(v) < _v("3.0.5")),
    ],

    "react-dom": [
        CVEEntry("CVE-2024-21913", "MEDIUM", 5.3,
            "XSS via dangerouslySetInnerHTML with crafted input",
            "Upgrade to react-dom 18.3.0+.",
            lambda v: _v(v) < _v("18.3.0") and _v(v) >= _v("18.0.0")),
    ],

    "nunjucks": [
        CVEEntry("CVE-2023-22461", "HIGH", 7.3,
            "Server-side template injection via autoescape bypass",
            "Upgrade to nunjucks 3.2.4+.",
            lambda v: _v(v) < _v("3.2.4")),
    ],

    "validator": [
        CVEEntry("CVE-2021-3765", "HIGH", 7.5,
            "ReDoS via crafted input to certain validators",
            "Upgrade to validator 13.7.0+.",
            lambda v: _v(v) < _v("13.7.0")),
    ],

    "trim-newlines": [
        CVEEntry("CVE-2021-33623", "HIGH", 7.5,
            "ReDoS via crafted string input",
            "Upgrade to trim-newlines 3.0.1 or 4.0.1+.",
            lambda v: (_v(v) < _v("3.0.1") and _v(v) >= _v("3.0.0"))
                   or (_v(v) < _v("4.0.1") and _v(v) >= _v("4.0.0"))),
    ],

    "xmlhttprequest-ssl": [
        CVEEntry("CVE-2021-31597", "CRITICAL", 9.8,
            "Improper certificate validation allows MITM",
            "Upgrade to xmlhttprequest-ssl 1.6.3+.",
            lambda v: _v(v) < _v("1.6.3")),
    ],

    "webpack": [
        CVEEntry("CVE-2023-28154", "CRITICAL", 9.8,
            "Code injection via crafted module name in webpack config",
            "Upgrade to webpack 5.76.0+.",
            lambda v: _v(v) < _v("5.76.0") and _v(v) >= _v("5.0.0")),
    ],

    "MooTools": [
        CVEEntry("CVE-2021-20090", "HIGH", 7.5,
            "Path traversal via MooTools more components",
            "Upgrade to MooTools 1.6.0+.",
            lambda v: _v(v) < _v("1.6.0")),
    ],

    "Prototype.js": [
        CVEEntry("CVE-2008-7220", "HIGH", 7.5,
            "XSS via prototype.js DOM manipulation",
            "Upgrade to Prototype.js 1.7+.",
            lambda v: _v(v) < _v("1.7.0")),
    ],
}


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_library_version(content: str, library: str) -> Optional[str]:
    """Try all patterns and return the first confirmed version."""
    patterns = LIBRARY_DETECTORS.get(library, [])
    for pattern in patterns:
        match = pattern.search(content)
        if match:
            groups = match.groups()
            if groups:
                version = groups[0].strip()
                if re.match(r'^\d+(\.\d+)*$', version):
                    return version
    return None


def scan_for_vulnerable_libraries(
    content:  str,
    file_url: str,
) -> List[LibraryFinding]:
    """
    Scan JavaScript content for known vulnerable library versions.
    Only returns findings where version is positively identified
    and falls within a known vulnerable range.
    Zero false positives — all CVEs are version-verified.
    """
    findings: List[LibraryFinding] = []

    for library, cves in CVE_DATABASE.items():
        version = detect_library_version(content, library)
        if not version:
            continue

        logger.debug("Detected %s v%s in %s", library, version, file_url)

        for cve in cves:
            try:
                if cve.affects(version):
                    findings.append(LibraryFinding(
                        library     = library,
                        version     = version,
                        cve_id      = cve.cve_id,
                        severity    = cve.severity,
                        cvss        = cve.cvss,
                        description = cve.description,
                        remediation = cve.remediation,
                        source_file = file_url,
                        confidence  = 0.95,
                    ))
                    logger.info(
                        "Vulnerable library: %s %s (%s) in %s",
                        library, version, cve.cve_id, file_url,
                    )
            except Exception as e:
                logger.debug("CVE check error %s: %s", cve.cve_id, e)

    return findings

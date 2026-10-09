"""
Static GraphQL surface tracker.

Extracts GQL operations, fragments, and type field usage from JS without
running introspection. Covers:
- gql`...` and gql(...) tagged template literals
- Inline query/mutation/subscription strings
- Fragment definitions and fragment spreads
- Variable signatures per operation
- Field usage per type (from fragment and inline selections)

Returns a GQLSurface object with deduped operations, fragments, and
a type->fields map for surface mapping.
"""

import re
import logging
from typing import List, Optional, Dict, Set
from dataclasses import dataclass, field

logger = logging.getLogger("bundlespy.analysis.gql_tracker")

# ── Patterns ──────────────────────────────────────────────────────────────────

# gql`...` - tagged template literal (graphql-tag, @apollo/client)
RE_GQL_TEMPLATE = re.compile(
    r'\bgql\s*`([\s\S]{1,8000}?)`',
    re.IGNORECASE,
)

# gql("...") or gql('...')
RE_GQL_CALL = re.compile(
    r'\bgql\s*\(\s*["\x27]([\s\S]{1,8000}?)["\x27]\s*\)',
    re.IGNORECASE,
)

# graphql`...` - alternative tag name used by relay, etc.
RE_GRAPHQL_TEMPLATE = re.compile(
    r'\bgraphql\s*`([\s\S]{1,8000}?)`',
    re.IGNORECASE,
)

# query/mutation/subscription OperationName($var: Type) { ... }
RE_OPERATION = re.compile(
    r'\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]{0,80})\s*'
    r'((?:\([^)]{0,400}\))?)\s*\{',
    re.IGNORECASE,
)

# fragment FragName on TypeName { ... }
RE_FRAGMENT = re.compile(
    r'\bfragment\s+([A-Za-z_][A-Za-z0-9_]{0,80})\s+on\s+([A-Za-z_][A-Za-z0-9_]{0,80})\s*\{',
    re.IGNORECASE,
)

# Variable definitions: ($id: ID!, $input: CreateUserInput)
RE_VARIABLE = re.compile(
    r'\$([A-Za-z_][A-Za-z0-9_]{0,60})\s*:\s*([A-Za-z_][A-Za-z0-9_![\]]{0,60})',
)

# Field names inside a GQL body (simple - one identifier per line or after {)
# Captures: "  fieldName" or "{ fieldName" - ignores directives and fragments
RE_FIELD_NAME = re.compile(
    r'(?:^|[{,\s])([a-z_][a-zA-Z0-9_]{0,60})(?:\s*[({:]|\s*$)',
    re.MULTILINE,
)

# Sensitive field names - same list as graphql.py but inline
_SENSITIVE_KEYWORDS = frozenset([
    "password", "token", "secret", "key", "auth", "credential",
    "ssn", "creditcard", "cardnumber", "cvv", "pin", "private",
    "internal", "admin", "role", "permission", "apikey",
])


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class GQLOperation:
    """One query/mutation/subscription found in JS."""
    op_type:     str           # query | mutation | subscription
    name:        str
    variables:   List[str]     # ["$id: ID!", "$input: CreateUserInput"]
    source_file: str
    line:        int
    evidence:    str = ""


@dataclass
class GQLFragment:
    """Fragment definition found in JS."""
    name:        str
    on_type:     str           # type name after "on"
    fields:      List[str]
    source_file: str
    line:        int


@dataclass
class GQLSurface:
    """Aggregated GraphQL surface for one scan."""
    operations:      List[GQLOperation]     = field(default_factory=list)
    fragments:       List[GQLFragment]      = field(default_factory=list)
    type_fields:     Dict[str, Set[str]]    = field(default_factory=dict)
    sensitive_fields: List[str]             = field(default_factory=list)
    endpoints:       List[str]              = field(default_factory=list)  # /graphql paths


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_line(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _evidence(content: str, pos: int, width: int = 80) -> str:
    start = max(0, pos - 20)
    end   = min(len(content), pos + width)
    return content[start:end].replace("\n", " ").strip()


def _parse_variables(var_str: str) -> List[str]:
    """Extract variable declarations from '($id: ID!, $input: Input)' string."""
    if not var_str:
        return []
    return [
        f"${m.group(1)}: {m.group(2)}"
        for m in RE_VARIABLE.finditer(var_str)
    ]


def _extract_fields(body: str) -> List[str]:
    """
    Extract field names from a GQL body (best-effort, not a full parser).
    Returns a deduplicated list of field names that look like GQL fields.
    """
    # Skip GQL keywords and directives
    _skip = frozenset([
        "query", "mutation", "subscription", "fragment", "on",
        "true", "false", "null", "if", "skip", "include",
        "deprecated", "specifiedBy",
    ])
    fields = []
    seen   = set()
    for m in RE_FIELD_NAME.finditer(body):
        name = m.group(1)
        if name in _skip or name in seen or len(name) < 2:
            continue
        # Skip if looks like a type (starts uppercase)
        if name[0].isupper():
            continue
        seen.add(name)
        fields.append(name)
    return fields


def _is_sensitive(name: str) -> bool:
    lower = name.lower().replace("_", "").replace("-", "")
    return any(k in lower for k in _SENSITIVE_KEYWORDS)


# ── Extraction ────────────────────────────────────────────────────────────────

def _extract_from_body(
    body:        str,
    source_file: str,
    body_start:  int,  # position in original content for line numbers
    content:     str,
    ops:         List[GQLOperation],
    frags:       List[GQLFragment],
    seen_ops:    Set[str],
    seen_frags:  Set[str],
) -> None:
    """Parse a GQL string body for operations and fragments."""

    # Operations
    for m in RE_OPERATION.finditer(body):
        op_type  = m.group(1).lower()
        name     = m.group(2)
        var_str  = m.group(3) or ""
        key      = f"{op_type}:{name}"
        if key in seen_ops:
            continue
        seen_ops.add(key)
        line  = _get_line(content, body_start) + body[:m.start()].count("\n")
        ev    = _evidence(body, m.start())
        ops.append(GQLOperation(
            op_type     = op_type,
            name        = name,
            variables   = _parse_variables(var_str),
            source_file = source_file,
            line        = line,
            evidence    = ev,
        ))

    # Fragments
    for m in RE_FRAGMENT.finditer(body):
        frag_name = m.group(1)
        on_type   = m.group(2)
        key       = f"frag:{frag_name}"
        if key in seen_frags:
            continue
        seen_frags.add(key)

        # Get the body of this fragment (everything between the { and its matching })
        brace_start = m.end() - 1   # position of the opening {
        depth       = 0
        frag_body   = ""
        for i, ch in enumerate(body[brace_start:], brace_start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    frag_body = body[brace_start+1:i]
                    break

        fields = _extract_fields(frag_body)
        line   = _get_line(content, body_start) + body[:m.start()].count("\n")
        frags.append(GQLFragment(
            name        = frag_name,
            on_type     = on_type,
            fields      = fields,
            source_file = source_file,
            line        = line,
        ))


def process_file(content: str, source_file: str) -> Optional[GQLSurface]:
    """
    Full GQL surface extraction for one JS file.
    Returns None if no GQL content found.
    """
    # Quick bail
    if "query" not in content and "mutation" not in content and "gql" not in content:
        return None

    ops:        List[GQLOperation] = []
    frags:      List[GQLFragment]  = []
    seen_ops:   Set[str]           = set()
    seen_frags: Set[str]           = set()

    def _parse(body: str, pos: int) -> None:
        _extract_from_body(body, source_file, pos, content, ops, frags, seen_ops, seen_frags)

    # gql`` tagged template literals
    for m in RE_GQL_TEMPLATE.finditer(content):
        _parse(m.group(1), m.start(1))

    # gql() calls
    for m in RE_GQL_CALL.finditer(content):
        _parse(m.group(1), m.start(1))

    # graphql`` alternative tag
    for m in RE_GRAPHQL_TEMPLATE.finditer(content):
        _parse(m.group(1), m.start(1))

    # Inline bare operations not inside a gql tag
    # (lower confidence but still useful)
    for m in RE_OPERATION.finditer(content):
        op_type = m.group(1).lower()
        name    = m.group(2)
        key     = f"{op_type}:{name}"
        if key in seen_ops:
            continue
        seen_ops.add(key)
        var_str = m.group(3) or ""
        ops.append(GQLOperation(
            op_type     = op_type,
            name        = name,
            variables   = _parse_variables(var_str),
            source_file = source_file,
            line        = _get_line(content, m.start()),
            evidence    = _evidence(content, m.start()),
        ))

    # Inline bare fragments not inside a gql tag
    for m in RE_FRAGMENT.finditer(content):
        frag_name = m.group(1)
        on_type   = m.group(2)
        key       = f"frag:{frag_name}"
        if key in seen_frags:
            continue
        seen_frags.add(key)
        frags.append(GQLFragment(
            name        = frag_name,
            on_type     = on_type,
            fields      = [],   # body not captured in this pass
            source_file = source_file,
            line        = _get_line(content, m.start()),
        ))

    if not ops and not frags:
        return None

    # Build type->fields map from fragments
    type_fields: Dict[str, Set[str]] = {}
    for frag in frags:
        if frag.fields:
            if frag.on_type not in type_fields:
                type_fields[frag.on_type] = set()
            type_fields[frag.on_type].update(frag.fields)

    # Find sensitive fields across all types
    sensitive = []
    for type_name, fields in type_fields.items():
        for f in fields:
            if _is_sensitive(f):
                sensitive.append(f"{type_name}.{f}")

    surface = GQLSurface(
        operations       = ops,
        fragments        = frags,
        type_fields      = type_fields,
        sensitive_fields = sensitive,
    )

    logger.debug(
        "gql_tracker: %d ops, %d frags, %d types, %d sensitive  [%s]",
        len(ops), len(frags), len(type_fields), len(sensitive), source_file,
    )

    return surface


def merge_surfaces(surfaces: List[GQLSurface]) -> GQLSurface:
    """
    Merge per-file GQLSurface objects into one deduplicated report.
    """
    merged = GQLSurface()
    seen_ops   = set()
    seen_frags = set()

    for s in surfaces:
        for op in s.operations:
            key = f"{op.op_type}:{op.name}"
            if key not in seen_ops:
                seen_ops.add(key)
                merged.operations.append(op)

        for frag in s.fragments:
            key = f"frag:{frag.name}"
            if key not in seen_frags:
                seen_frags.add(key)
                merged.fragments.append(frag)

        for type_name, fields in s.type_fields.items():
            if type_name not in merged.type_fields:
                merged.type_fields[type_name] = set()
            merged.type_fields[type_name].update(fields)

        for sf in s.sensitive_fields:
            if sf not in merged.sensitive_fields:
                merged.sensitive_fields.append(sf)

    return merged

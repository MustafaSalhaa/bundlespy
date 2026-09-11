"""
GraphQL Introspection Module.

When a GraphQL endpoint is detected and --graphql is enabled,
performs a safe introspection query to map the full schema.
Never makes mutations. Never sends sensitive data.
Reports types, queries, mutations, and fields.
"""

import json
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

import requests
import urllib3

from ..safety.network import validate_url
from ..utils.stealth import random_ua

urllib3.disable_warnings()
logger = logging.getLogger("bundlespy.analysis.graphql")

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        isDeprecated
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
      inputFields { name type { name kind ofType { name kind } } }
    }
  }
}
"""


@dataclass
class GraphQLSchema:
    endpoint:      str
    query_type:    str = ""
    mutation_type: str = ""
    types:         List[Dict] = field(default_factory=list)
    queries:       List[str]  = field(default_factory=list)
    mutations:     List[str]  = field(default_factory=list)
    sensitive_fields: List[str] = field(default_factory=list)
    raw_schema:    Optional[dict] = None
    error:         Optional[str]  = None


SENSITIVE_FIELD_KEYWORDS = [
    "password", "token", "secret", "key", "auth", "credential",
    "ssn", "credit_card", "card_number", "cvv", "pin", "private",
    "internal", "admin", "role", "permission",
]


def _is_sensitive_field(name: str) -> bool:
    lower = name.lower()
    return any(k in lower for k in SENSITIVE_FIELD_KEYWORDS)


def introspect(
    endpoint: str,
    timeout:  int  = 10,
    stealth:  bool = False,
) -> Optional[GraphQLSchema]:
    """
    Run a GraphQL introspection query against an endpoint.
    Returns parsed schema or None if introspection is disabled.
    """
    safe, reason = validate_url(endpoint)
    if not safe:
        logger.warning("GraphQL endpoint blocked: %s", reason)
        return None

    headers = {
        "User-Agent":   random_ua() if stealth else "BundleSpy/1.0.0 (authorized security assessment)",
        "Content-Type": "application/json",
        "Accept":       "application/json",
    }

    schema = GraphQLSchema(endpoint=endpoint)

    try:
        resp = requests.post(
            endpoint,
            json={"query": INTROSPECTION_QUERY},
            headers=headers,
            timeout=timeout,
            verify=False,
        )

        if resp.status_code not in range(200, 300):
            schema.error = f"HTTP {resp.status_code}"
            return schema

        data = resp.json()

        if "errors" in data and not "data" in data:
            schema.error = "Introspection disabled or unauthorized"
            return schema

        gql_schema = data.get("data", {}).get("__schema", {})
        if not gql_schema:
            schema.error = "Empty schema response"
            return schema

        schema.raw_schema   = gql_schema
        schema.query_type   = (gql_schema.get("queryType")    or {}).get("name", "")
        schema.mutation_type = (gql_schema.get("mutationType") or {}).get("name", "")

        for type_def in gql_schema.get("types", []):
            name   = type_def.get("name", "")
            kind   = type_def.get("kind", "")
            fields = type_def.get("fields") or []

            # Skip internal GraphQL types
            if name.startswith("__"):
                continue

            schema.types.append({"name": name, "kind": kind, "fields": [
                f["name"] for f in fields
            ]})

            # Extract queries and mutations
            if name == schema.query_type:
                schema.queries = [f["name"] for f in fields]
            elif name == schema.mutation_type:
                schema.mutations = [f["name"] for f in fields]

            # Flag sensitive fields
            for field_def in fields:
                fname = field_def.get("name", "")
                if _is_sensitive_field(fname):
                    schema.sensitive_fields.append(f"{name}.{fname}")

        logger.info(
            "GraphQL introspection: %d types, %d queries, %d mutations, %d sensitive fields",
            len(schema.types), len(schema.queries),
            len(schema.mutations), len(schema.sensitive_fields),
        )
        return schema

    except requests.exceptions.Timeout:
        schema.error = "Request timed out"
        return schema
    except Exception as e:
        schema.error = str(e)
        return schema


def find_graphql_endpoints(endpoints) -> List[str]:
    """Filter endpoint list for GraphQL candidates."""
    graphql_paths = ["/graphql", "/api/graphql", "/gql", "/query", "/graphiql"]
    found = []
    for ep in endpoints:
        url = ep.url.lower()
        if any(path in url for path in graphql_paths):
            found.append(ep.url)
    return found

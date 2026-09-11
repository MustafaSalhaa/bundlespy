"""
Authorization confirmation.
The user must explicitly confirm they have authorization before any scan begins.
This is not a legal disclaimer - it's a required operational step.
"""

import sys


AUTHORIZATION_PROMPT = """
+------------------------------------------------------------------+
|                    AUTHORIZATION REQUIRED                        |
+------------------------------------------------------------------+

BundleSpy will send HTTP requests to the target you specify.

Before proceeding, confirm that you have explicit written authorization
to perform security testing on this target.

Unauthorized scanning is illegal. You are responsible for ensuring
your assessment is within scope and properly authorized.

Target: {target}

I confirm that I have authorization to assess this target [y/N]: """


def require_authorization(target: str, skip: bool = False) -> bool:
    """
    Prompt the operator to confirm authorization.
    Returns True if confirmed, False otherwise.

    skip=True only for demo mode (offline, no real target).
    """
    if skip:
        return True

    prompt = AUTHORIZATION_PROMPT.format(target=target)
    try:
        answer = input(prompt).strip().lower()
        if answer == "y":
            print("\n  Authorization confirmed. Starting scan.\n")
            return True
        else:
            print("\n  Scan cancelled. Authorization not confirmed.\n")
            return False
    except (KeyboardInterrupt, EOFError):
        print("\n\n  Scan cancelled.\n")
        return False

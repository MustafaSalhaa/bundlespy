"""
CLI banner for BundleSpy.
"""

from .config import PROJECT_NAME, PROJECT_VERSION, AUTHOR_NAME, GITHUB_URL


BANNER = f"""
+------------------------------------------------------------------+
|        BundleSpy - JavaScript Intelligence & Secret Scanner        |
|               Authorized Security Assessments Only               |
+------------------------------------------------------------------+
  Author  : {AUTHOR_NAME}
  Version : {PROJECT_VERSION}
  GitHub  : {GITHUB_URL}
"""

def print_banner(no_color: bool = False) -> None:
    if no_color:
        print(BANNER)
        return
    cyan  = "\033[96m"
    bold  = "\033[1m"
    reset = "\033[0m"
    print(f"{cyan}{bold}{BANNER}{reset}")

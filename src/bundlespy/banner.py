"""
CLI banner for BundleSpy.
"""

from .config import PROJECT_NAME, PROJECT_VERSION, AUTHOR_NAME, GITHUB_URL

G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
R  = "\033[91m"   # red
DM = "\033[90m"   # dark/grey
B  = "\033[1m"    # bold
RS = "\033[0m"    # reset


def print_banner(no_color: bool = False) -> None:
    if no_color:
        print(f"""
  BUNDLESPY v{PROJECT_VERSION}
  JavaScript Intelligence | Secret Exposure | Endpoint Discovery
  Author  : {AUTHOR_NAME}
  GitHub  : {GITHUB_URL}
  [!] For authorized security assessments only
""")
        return

    print(f"""
{G}
  ██████╗ ██╗   ██╗███╗   ██╗██████╗ ██╗     ███████╗███████╗██████╗ ██╗   ██╗
  ██╔══██╗██║   ██║████╗  ██║██╔══██╗██║     ██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝
  ██████╔╝██║   ██║██╔██╗ ██║██║  ██║██║     █████╗  ███████╗██████╔╝ ╚████╔╝
  ██╔══██╗██║   ██║██║╚██╗██║██║  ██║██║     ██╔══╝  ╚════██║██╔═══╝   ╚██╔╝
  ██████╔╝╚██████╔╝██║ ╚████║██████╔╝███████╗███████╗███████║██║        ██║
  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝        ╚═╝
{RS}
{DM}  ────────────────────────────────────────────────────────────────────────{RS}
{G}  ▸{RS} JavaScript Intelligence {DM}│{RS} Secret Exposure {DM}│{RS} Endpoint Discovery
{DM}  ────────────────────────────────────────────────────────────────────────{RS}
{Y}  Author  {DM}:{RS} {AUTHOR_NAME}
{Y}  Version {DM}:{RS} {PROJECT_VERSION}
{Y}  GitHub  {DM}:{RS} {GITHUB_URL}
{Y}  PyPI    {DM}:{RS} https://pypi.org/project/bundlespy
""")

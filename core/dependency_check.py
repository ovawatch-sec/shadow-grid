import shutil
from .colors import RED, GREEN, ORANGE, RESET, BLUE, PURPLE

# (tool_name, install_command)
REQUIRED_TOOLS = [
    ('assetfinder',  'go install github.com/tomnomnom/assetfinder@latest'),
    ('subfinder',    'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'),
    ('amass',        'go install github.com/owasp-amass/amass/v4/...@latest'),
    ('shuffledns',   'go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest'),
    ('alterx',       'go install github.com/projectdiscovery/alterx/cmd/alterx@latest'),
    ('dnsx',         'go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest'),
    ('httpx',        'go install github.com/projectdiscovery/httpx/cmd/httpx@latest'),
    ('naabu',        'go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest'),
    ('nuclei',       'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'),
    ('katana',       'go install github.com/projectdiscovery/katana/cmd/katana@latest'),
    ('gowitness',    'go install github.com/sensepost/gowitness@latest'),
    ('waybackurls',  'go install github.com/tomnomnom/waybackurls@latest'),
    ('gau',          'go install github.com/lc/gau/v2/cmd/gau@latest'),
    ('urlfinder',    'go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest'),
    ('asnmap',       'go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest'),
]

OPTIONAL_TOOLS = [
    ('whatweb', 'sudo apt install whatweb  OR  gem install whatweb'),
    ('dig',     'sudo apt install dnsutils'),
    ('whois',   'sudo apt install whois'),
]


def check_dependencies(skip_tools: set = None) -> list:
    """
    Check required and optional tools. Returns list of missing required tools.
    Skips tools listed in skip_tools.
    """
    skip_tools = skip_tools or set()
    missing = []

    print(f"\n{PURPLE}[Dependency Check]{RESET}")

    max_len = max(len(t) for t, _ in REQUIRED_TOOLS + OPTIONAL_TOOLS)

    for tool, install_cmd in REQUIRED_TOOLS:
        if tool in skip_tools:
            print(f"  {ORANGE}[SKIP] {tool:<{max_len}}{RESET}")
            continue
        if shutil.which(tool):
            print(f"  {GREEN}[ OK ] {tool:<{max_len}}{RESET}")
        else:
            print(f"  {RED}[MISS] {tool:<{max_len}}  →  {install_cmd}{RESET}")
            missing.append(tool)

    print(f"\n{PURPLE}[Optional]{RESET}")
    for tool, install_cmd in OPTIONAL_TOOLS:
        if shutil.which(tool):
            print(f"  {GREEN}[ OK ] {tool:<{max_len}}{RESET}")
        else:
            print(f"  {ORANGE}[ -- ] {tool:<{max_len}}  →  {install_cmd}{RESET}")

    if missing:
        print(f"\n{RED}[!] Missing required tools: {', '.join(missing)}{RESET}")
        print(f"{RED}[!] Run setup.sh to install all, or use --skip-tools to bypass{RESET}\n")

    return missing

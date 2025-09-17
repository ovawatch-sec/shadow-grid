import requests
import subprocess
import shutil
from core.colors import RED, GREEN, RESET, PURPLE, BLUE, ORANGE, PINK
def run_assetfinder(domain, outfile=None):
    from core.utils import run_command
    return run_command(["assetfinder", "--subs-only", domain],str(outfile))


def run_subfinder(domain, outfile=None):
    from core.utils import run_command
    return run_command(["subfinder", "-silent", "-d", domain,'-o',str(outfile)])


def run_amass(domain, outfile=None, timeout=300):
    """
    Run `amass enum -passive -d <domain>` and extract the hostnames.
    Replicates: cut -d']' -f2 | awk '{print $1}'
    Returns a sorted list of unique names. Writes to outfile if provided.
    """
    cmd = ["amass", "enum", "-passive", "-d", domain]
    print(f"{GREEN}[+] Running: {' '.join(cmd)}{RESET}")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        print("{RED}[-] amass timed out{RESET}")
        return []

    # prefer stdout; if amass returns nothing and wrote to stderr, report it
    if proc.returncode != 0 and not proc.stdout:
        print(f"{RED}[-] amass failed: {proc.stderr.strip()}{RESET}")
        return []

    lines = proc.stdout.splitlines()

    names = set()
    for line in lines:
        if not line:
            continue
        # split on first ']' and take everything after it (like cut -d']' -f2)
        if ']' in line:
            after = line.split(']', 1)[1]
        else:
            after = line
        after = after.strip()
        if not after:
            continue
        # take the first whitespace-separated token (like awk '{print $1}')
        token = after.split()[0]
        # trim common trailing punctuation that might sneak in
        token = token.strip(" ,;\"'")
        # basic sanity check: token should contain at least one dot (simple heuristic for domains)
        if token and ('.' in token or token == domain):
            names.add(token)

    result = sorted(names)

    if outfile:
        try:
            with open(outfile, "w") as f:
                f.write("\n".join(result))
        except OSError as e:
            print(f"{RED}[-] Error writing to {outfile}: {e}{RESET}")

    return result


def run_sublist3r(domain, outfile=None):
    from core.utils import run_command
    return run_command(["sublist3r", "-d", domain,'-o',str(outfile)])


def run_crt(domain, outfile=None):
    
    url = f"https://crt.sh?q={domain}&output=json"
    print(f"{GREEN}[+] Quering {url}{RESET}")
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"{RED}[-] Error fetching data: {e}{RESET}")
        return []

    try:
        data = resp.json()
    except ValueError:
        print(f"{RED}[-] Error parsing JSON response{RESET}")
        return []

    # Collect all unique certificate names
    names = sorted({entry["name_value"] for entry in data if "name_value" in entry})

    # Save to file if requested
    if outfile:
        with open(outfile, "w") as f:
            f.write("\n".join(names))

    return names

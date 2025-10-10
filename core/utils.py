from subprocess import CompletedProcess
from typing import List
from .colors import RED, GREEN, RESET, PURPLE, BLUE, ORANGE, PINK


def run_command(cmd,outfile=None,show=True):
    import subprocess
    if  show:
        outfile_info =''
        if '-o' not in cmd and outfile:
            outfile_info= f', output file = {outfile}'
        print(f"{GREEN}[+] Running: {' '.join(cmd)}{outfile_info}{RESET}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result

def save_to_file(result:list[str],outfile=None):
    if outfile:
        with open(outfile, 'w') as f:
            f.write("\n".join(result))

def save_to_file_with_cmd_result(result:CompletedProcess[str],outfile=None):
    if outfile:
        with open(outfile,'w') as f:
            f.write(result.stdout)

def filter_out_of_scope(domain,domains, oos_list):
    import fnmatch
    filtered = []
    for d in domains:
        if not any(fnmatch.fnmatch(d, pattern) for pattern in oos_list):
            filtered.append(d)
    doms = [d for d in filtered if domain in d]
    return list(set(doms))



def load_out_of_scope(filepath):
    from pathlib import Path
    if not filepath or not Path(filepath).exists():
        return []
    with open(filepath) as f:
        return [line.strip() for line in f if line.strip()]

def extract_domains(lines:List[str]) -> List[str]:
    import re
    DOMAIN_RE = re.compile(
        r'\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b',
        re.IGNORECASE
    )
    """
    Extract domain names (including subdomains) from a block of text.

    - strips ANSI/terminal color escapes
    - finds domains like example.com, sub.example.co.za, www.foo.bar
    - returns unique domains preserving first-seen order
    """
    domains = []
    seen = set()
    for line in lines:
        # remove ANSI escapes
        clean = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', line)
        # search for domains in line
        for match in DOMAIN_RE.findall(clean):
            domain = match.lower()
            if domain not in seen:
                seen.add(domain)
                domains.append(domain)
    return domains
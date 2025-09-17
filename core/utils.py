from .colors import RED, GREEN, RESET, PURPLE, BLUE, ORANGE, PINK


def run_command(cmd, outfile=None):
    import subprocess
    print(f"""
{GREEN}[+] Running: {' '.join(cmd)}{RESET}
""")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,shell=True)
    if outfile:
        with open(outfile, 'w') as f:
            f.write(result.stdout)
    return result.stdout.splitlines()


def filter_out_of_scope(domains, oos_list):
    import fnmatch
    filtered = []
    for d in domains:
        if not any(fnmatch.fnmatch(d, pattern) for pattern in oos_list):
            filtered.append(d)
    return list(set(filtered))


def load_out_of_scope(filepath):
    from pathlib import Path
    if not filepath or not Path(filepath).exists():
        return []
    with open(filepath) as f:
        return [line.strip() for line in f if line.strip()]
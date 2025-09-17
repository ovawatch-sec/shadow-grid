import subprocess
from pathlib import Path
from core.colors import RED,RESET,GREEN
def run_gowitness(alive_domains, output_dir):
    """
    Run gowitness against a file of alive domains.
    Expects alive_domains (list of URLs) or a path to a file.
    Saves screenshots into output_dir/screenshots.
    """

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    screenshots_dir = output_dir / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    # If alive_domains is a list, save it into alive_subs.txt
    input_file = output_dir / "alive_subs.txt"
    if isinstance(alive_domains, (list, set)):
        with input_file.open("w") as f:
            f.write("\n".join(alive_domains))
    else:
        input_file = Path(alive_domains)

    cmd = [
        "gowitness", "scan", "file",
        "-f", str(input_file),
        "--no-http",
        "--timeout", "10",
        "-s", str(screenshots_dir)
    ]

    print(f"{GREEN}[+] Running: {' '.join(cmd)}{RESET}")

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if proc.returncode != 0:
        print(f"{RED}[-] gowitness failed: {proc.stderr.strip()}{RESET}")
    else:
        print(f"{GREEN}[+] gowitness finished. Screenshots in {screenshots_dir}{RESET}")

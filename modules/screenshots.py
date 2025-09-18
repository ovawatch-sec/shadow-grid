import subprocess
from pathlib import Path
from core.colors import RED,RESET,GREEN
from core.utils import run_command

def run_gowitness(alive_subs, output_dir,http_proto=443):
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
    cmd = [
        "gowitness", "scan", "file",
        "-f", str(alive_subs),
        "--timeout", "300",
        "-s", str(screenshots_dir)
    ]
    if http_proto == 443:
        cmd.append("--no-http")

    proc = run_command(cmd)

    if proc.returncode != 0:
        print(f"{RED}[-] gowitness failed: {proc.stderr.strip()}{RESET}")

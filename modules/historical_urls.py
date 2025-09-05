# modules/historical_urls.py
from core.utils import run_command
from pathlib import Path

def run_waybackurls(domain, output_dir: Path):
    output_file = output_dir / "wayback_urls.txt"
    run_command(["waybackurls", domain], outfile=output_file)
    return [line.strip() for line in open(output_file)]

def run_gau(domain, output_dir: Path):
    output_file = output_dir / "gau_urls.txt"
    run_command(["gau", domain], outfile=output_file)
    return [line.strip() for line in open(output_file)]

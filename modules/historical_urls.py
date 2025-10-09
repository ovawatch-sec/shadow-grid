# modules/historical_urls.py
from core.utils import run_command,save_to_file
from pathlib import Path

def run_waybackurls(domain, output_dir: Path):
    output_file = output_dir / f"{domain}_wayback_urls.txt"
    result = run_command(["waybackurls", domain], outfile=output_file)
    save_to_file(set(result.stdout.splitlines()),output_file)
    return [line.strip() for line in open(output_file)]

def run_urlfinder(domain, output_dir: Path):
    output_file = output_dir / f"{domain}_urlfinder.txt"
    result = run_command(["urlfinder -d ", domain], outfile=output_file)
    save_to_file(set(result.stdout.splitlines()),output_file)
    return [line.strip() for line in open(output_file)]


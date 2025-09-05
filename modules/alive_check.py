def run_httpx(domains, output_dir, rate_limit, custom_headers):
    from core.utils import run_command
    import subprocess
    alive_file = output_dir / 'alive.txt'
    input_file = output_dir / 'all_subs.txt'
    with open(input_file) as infile, open(alive_file, 'w') as outfile:
        proc = subprocess.Popen(['httprobe'], stdin=infile, stdout=outfile)
        proc.communicate()
    return [line.strip() for line in open(alive_file)]

def run_httpx(domains, output_dir, rate_limit, custom_headers):
    from core.utils import run_command
    alive_file = output_dir / 'alive.txt'
    input_file = output_dir / 'all_subs.txt'
    with open(input_file, 'w') as f:
        f.write('\n'.join(domains))
    cmd = [
        'httprobe ', '-silent', '-l', str(input_file),
        '-rate-limit', str(rate_limit), '-o', str(alive_file)
    ]
    for header in custom_headers:
        cmd.extend(['-H', header])
    run_command(cmd)
    return [line.strip() for line in open(alive_file)]

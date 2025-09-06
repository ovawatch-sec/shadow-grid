def run_httprobe(output_dir):
    from core.utils import run_command
    outfile = output_dir / 'alive_urls.txt'
    input_file = output_dir / 'all_subs.txt'
    return run_command(["cat", str(input_file), "|","httprobe"],str(outfile))

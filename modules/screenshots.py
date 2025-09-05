def run_gowitness(alive_domains, output_dir):
    from core.utils import run_command
    input_file = output_dir / 'alive.txt'
    run_command(["gowitness", "file", "-f", str(input_file), "--timeout", "10", "--disable-verify", "-P", str(output_dir / "screenshots")])

def run_gowitness(alive_domains, output_dir):
    from core.utils import run_command
    input_file = output_dir / 'alive.txt'
    run_command(["gowitness","scan" ,"file", "-f", str(input_file), "--no-http","--timeout", "10", "-s", str(output_dir / "screenshots")])

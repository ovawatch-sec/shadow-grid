from core.colors import PURPLE


if __name__ == '__main__':
    import argparse
    from core.banner import banner
    from core.utils import load_out_of_scope, filter_out_of_scope
    import modules.subdomain_enum as enum
    import modules.alive_check as alive
    import modules.screenshots as screenshots
    from modules import historical_urls as hist
    from core.colors import RED,RESET,GREEN,BLUE
    from pathlib import Path

    banner()
    try:
        parser = argparse.ArgumentParser(description='Recon Automation Framework')
        parser.add_argument('target', help='Domain or file with domains')
        parser.add_argument('--oos', help='File with out-of-scope domains/wildcards')
        parser.add_argument('--rate', type=int, default=2, help='Max requests per second')
        parser.add_argument('--header', action='append', help='Custom header(s)')
        parser.add_argument('--user-agent', help='Custom User Agent')
        parser.add_argument(
        '--skip-tools',
        help='Comma-separated list of tools to skip (e.g., amass,httpx,gowitness)',
        default=''
    )
        args = parser.parse_args()
        skip_tools = [t.strip().lower() for t in args.skip_tools.split(',') if t.strip()]

        # Print skipped tools if any
        if skip_tools:
            skipped = ", ".join(skip_tools)
            print(f"""
        {RED}[!] Skipped tools:{RESET} {BLUE}{skipped}{RESET}
============================================================================================================================================================
        """)
        target_path = Path(args.target)
        domains = []
        if target_path.exists():
            with open(target_path) as f:
                domains = [line.strip() for line in f if line.strip()]
        else:
            domains = [args.target]

        for domain in domains:
            output_dir = Path('output') / domain
            output_dir.mkdir(parents=True, exist_ok=True)
            oos_list = load_out_of_scope(args.oos)

            # Run each tool individually and save to files
            tools_results = {}
            all_subs = set()

            if 'assetfinder' not in skip_tools:
                af_file = output_dir / "assetfinder.txt"
                tools_results['assetfinder'] = enum.run_assetfinder(domain, outfile=af_file)

                # read the content of the file
                with open(af_file, 'r') as f:
                    all_subs.update(line.strip() for line in f)

            if 'subfinder' not in skip_tools:
                sf_file = output_dir / "subfinder.txt"
                tools_results['subfinder'] = enum.run_subfinder(domain, outfile=sf_file)

                # read the content of the file
                with open(sf_file, 'r') as f:
                    all_subs.update(line.strip() for line in f)

            if 'sublist3r' not in skip_tools:
                sl3_file = output_dir / "sublist3r.txt"
                tools_results['sublist3r'] = enum.run_sublist3r(domain, outfile=sl3_file)

                # read the content of the file
                with open(sl3_file, 'r') as f:
                    all_subs.update(line.strip() for line in f)

            if 'amass' not in skip_tools:
                am_file = output_dir / "amass.txt"
                tools_results['amass'] = enum.run_amass(domain, outfile=am_file)

                # read the content of the file
                with open(am_file, 'r') as f:
                    all_subs.update(line.strip() for line in f)

            # Apply out-of-scope filter
            all_subs = filter_out_of_scope(all_subs,oos_list)
            # Save the final merged subdomains
            all_file = output_dir / "all_subs.txt"
            with open(all_file, 'w') as f:
                f.write("\n".join(sorted(all_subs)))

            # get alive sub domains
            alive.run_httprobe(output_dir)
            
            # read alive urls 
            alive_urls = output_dir / 'alive_urls.txt'
            alive_domains = []

            # Read alive urls and clean them
            with open(alive_urls, 'r') as f:
                for line in f:
                    domain = line.strip().replace('https://', '').replace('http://', '')
                    alive_domains.append(domain)

            # Save the alive domains
            alive_file = output_dir / 'alive_subs.txt'
            with open(alive_file, 'w') as f:
                f.write("\n".join(alive_domains))

            if alive_domains:
                screenshots.run_gowitness(alive_domains, output_dir)

            # fetch historical urls
            if 'waybackurls' not in skip_tools:
                hist.run_waybackurls(domain, output_dir)
        
        print(f"""
============================================================================================================================================================
        {GREEN}[+] Recon Completed {RESET}
============================================================================================================================================================
        """)
    except KeyboardInterrupt as e:
        print(f"""
============================================================================================================================================================
        {RED}[-] Keyboard Interrupt Error Occured!!! {RESET}
============================================================================================================================================================
        """)
    except:
        print(f"""
============================================================================================================================================================
        {RED}[-] An Error Occured!!! {RESET}
============================================================================================================================================================
        """)
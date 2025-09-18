import sys
from core.colors import PURPLE


if __name__ == '__main__':
    import argparse
    from core.banner import banner
    from core.utils import load_out_of_scope, filter_out_of_scope, save_to_file,run_command
    import modules.web_scan as web_scan
    import modules.subdomain_enum as enum
    import modules.alive_check as alive
    import modules.screenshots as screenshots
    from modules import historical_urls as hist
    from core.colors import RED,RESET,GREEN,BLUE
    from pathlib import Path

    banner()
    try:
        parser = argparse.ArgumentParser(description='Recon Automation Framework')
        parser.add_argument('-t','--target', help='Domain or file with domains')
        parser.add_argument('--oos', help='File with out-of-scope domains/wildcards')
        parser.add_argument('--rate-limit', type=int, default=2, help='Max requests per second (default=2)')
        parser.add_argument('-p','--port', type=int,default=8000, help='Dashboard web port (defaut: 8000)')
        parser.add_argument('-H','--headers', action='append', help='Custom header(s) (example. Accept:application/json "User-Agent: <username>-Mozilla/5.0 Firefox/128.0" )')
        parser.add_argument('-o','--output', default='output', help='Results output file')
        parser.add_argument('--http-proto', default=443,type=int, help='Request protocol')
        parser.add_argument('-l','--list',action='store_true',help='List of tools used')
        parser.add_argument('--fuzz',default=False,action='store_true',help='Enable subdomain fuzzing')
        parser.add_argument('-w','--wordlist',default=None,help='Wordlist')
        parser.add_argument('--dashboard',default=True,action='store_true',help='Enable dashboard for the results at http://localhost:8000/app')
        parser.add_argument(
        '--skip-tools',
        help='Comma-separated list of tools to skip (e.g., amass,httprobe,gowitness)',
        default=''
    )
        args = parser.parse_args()
        
        
        # Get the tools list 
        tools_list = ['assetfinder','subfinder','sublist3r','amass','httprobe','crt.sh','waybackurls','gowitness','nuclei']

        if args.list:
            print(f"{PURPLE}[!] {BLUE}{', '.join(tools_list)}{RESET}")
            sys.exit(0)

        # Get Skipped tools
        skip_tools = [t.strip().lower() for t in args.skip_tools.split(',') if t.strip()]

        # Print enabled tools if any
        if args.fuzz:
            skipped = ", ".join(skip_tools) 
            print(f"{PURPLE}[!] Fuzzing Enabled{RESET}")

        if args.dashboard:
            skipped = ", ".join(skip_tools) 
            print(f"{PURPLE}[!] Recon Dashboard Enabled{RESET}")

        # Print skipped tools if any
        if skip_tools:
            skipped = ", ".join(skip_tools) 
            print(f"{PURPLE}[!] Skipped tools:{RESET} {BLUE}{skipped}{RESET}")
        target_path = Path(args.target)
        domains = []
        if target_path.exists():
            with open(target_path) as f:
                domains = [line.strip() for line in f if line.strip()]
        else:
            domains = [args.target]

        for domain in domains:
            print(f"{PURPLE}[!] Target Domain {domain}{RESET}")
            output_dir_name = args.output
            output_dir = Path(output_dir_name) / domain
            output_dir.mkdir(parents=True, exist_ok=True)

            # create the raw directory
            raw_output_dir = Path(output_dir) / 'raw'
            raw_output_dir.mkdir(parents=True, exist_ok=True)

             
            # create the wayback directory
            wayback_output_dir = Path(output_dir) / 'waybackurls'
            wayback_output_dir.mkdir(parents=True, exist_ok=True)
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
                tools_results['amass'] = enum.run_amass(domain, raw_output_dir,outfile=am_file)

                # read the content of the file
                with open(am_file, 'r') as f:
                    all_subs.update(line.strip() for line in f)

            if 'crt.sh' not in skip_tools:
                crt_file = output_dir / "crt.sh.txt"
                tools_results['crt.sh'] = enum.run_crt(domain, outfile=crt_file)

                # read the content of the file
                with open(crt_file, 'r') as f:
                    all_subs.update(line.strip() for line in f)

            # Apply out-of-scope filter
            all_subs = filter_out_of_scope(all_subs,oos_list)

            # Save the final merged subdomains
            all_file = output_dir / "all_subs.txt"
            save_to_file(sorted(all_subs),all_file)

            # get alive sub domains
            if 'httprobe' not in skip_tools:
                alive_urls = output_dir / 'alive_urls.txt'
                alive.run_httprobe(all_file,alive_urls, http_proto=args.http_proto)

                # read alive urls 
                alive_domains = set()

                # Read alive urls and clean them
                with open(alive_urls, 'r') as f:
                    for line in f:
                        domain = line.strip().replace('https://', '').replace('http://', '')
                        alive_domains.add(domain)

                # Save the alive domains
                alive_file = output_dir / 'alive_subs.txt'
                save_to_file(alive_domains,alive_file)

                if alive_domains and 'gowitness' not in skip_tools:
                    screenshots.run_gowitness(alive_file, output_dir,http_proto=args.http_proto)
            elif 'gowitness' not in skip_tools:
                screenshots.run_gowitness(alive_file, output_dir,http_proto=args.http_proto)

            # fetch historical urls
            if 'waybackurls' not in skip_tools:
                for dom in alive_domains:
                    hist.run_waybackurls(dom, wayback_output_dir)
            
            # check for vulnerabilities using nuclei 
            if 'nuclei' not in skip_tools:
                web_scan.run_nuclei(alive_file,raw_output_dir)

            # fuzz the domain if enabled 
            if args.fuzz:
                for dom in alive_domains:
                    web_scan.run_fuzzing(dom, raw_output_dir,args.rate_limit, args.wordlist,str(args.headers[0]),http_proto=args.http_proto)

        # launch the web dashboard 
        if args.dashboard:
            print(f"{GREEN}[+] Launching the dashboard on port {args.port}, visit {PURPLE}http://localhost:{args.port}/app{GREEN} to access it{RESET}")
            run_command(['python3','-m','http.server',f'{args.port}'])

        print(f"""
============================================================================================================================================
{GREEN}[+] Recon Completed {RESET}
============================================================================================================================================
        """)
    except KeyboardInterrupt as e:
        print(f"""
============================================================================================================================================
{RED}[-] Keyboard Interrupt Error Occured!!! {RESET}
============================================================================================================================================
        """)
    except Exception as e:
        print(f"""
============================================================================================================================================
{RED}[-] An Error Occured!!! \n{e}{RESET}
============================================================================================================================================
        """)
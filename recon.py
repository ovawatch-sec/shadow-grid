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
        parser.add_argument('-pk','--pd-key', help='Project Discovery Key( required for running chaos-client )')
        parser.add_argument('--rate-limit', type=int, default=2, help='Max requests per second (default=2)')
        parser.add_argument('-p','--port', type=int,default=1337, help='Dashboard web port (defaut: 1337)')
        parser.add_argument('-H','--headers', action='append', help='Custom header(s) (example. Accept:application/json "User-Agent: <username>-Mozilla/5.0 Firefox/128.0" )')
        parser.add_argument('-l','--list',action='store_true',help='List of tools used')
        parser.add_argument('-w','--wordlist',default=None,help='Wordlist')
        parser.add_argument('--dashboard',default=True,action='store_true',help='Enable dashboard for the results at http://localhost:1337/app')
        parser.add_argument(
        '--skip-tools',
        help='Comma-separated list of tools to skip (e.g., amass,assetfinder,alterx)',
        default=''
    )
        args = parser.parse_args()
        
        
        # Get the tools list 
        tools_list = ['assetfinder','subfinder','shuffledns','amass','alterx','waybackurls','gowitness','nuclei','urlfinder','katana']

        if args.list:
            print(f"{PURPLE}[!] {BLUE}{', '.join(tools_list)}{RESET}")
            sys.exit(0)

        # Get Skipped tools
        skip_tools = [t.strip().lower() for t in args.skip_tools.split(',') if t.strip()]

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
            # Data directory
            data_dir = Path('data')
            data_dir.mkdir(parents=True, exist_ok=True)

            output_dir_name = 'output'
            output_dir = Path(output_dir_name) / domain
            output_dir.mkdir(parents=True, exist_ok=True)

            # create the raw directory
            raw_output_dir = Path(output_dir) / 'raw'
            raw_output_dir.mkdir(parents=True, exist_ok=True)

             
            # create the wayback directory
            wayback_output_dir = Path(output_dir) / 'waybackurls'
            wayback_output_dir.mkdir(parents=True, exist_ok=True)
      

            # create the urlfinder directory
            urlfinder_output_dir = Path(output_dir) / 'urlfinder'
            urlfinder_output_dir.mkdir(parents=True, exist_ok=True)

            # create the katana directory
            katana_output_dir = Path(output_dir) / 'katana'
            katana_output_dir.mkdir(parents=True, exist_ok=True)
            oos_list = load_out_of_scope(args.oos)
            
            # Run each tool individually and save to files
            tools_results = {}
            subdomains = set()

            if 'assetfinder' not in skip_tools:
                af_file = output_dir / "assetfinder.txt"
                enum.run_assetfinder(domain, outfile=af_file)

            if 'subfinder' not in skip_tools:
                sf_file = output_dir / "subfinder.txt"
                enum.run_subfinder(domain, outfile=sf_file)

            if 'shuffledns' not in skip_tools:
                sdns_file = output_dir / "shuffledns.txt"
                enum.run_shuffledns(domain, data_dir, args.wordlist , outfile=sdns_file)

            if 'chaos-client' not in skip_tools:
                chaos_file = output_dir / "chaos-client.txt"
                enum.run_chaos_client(domain, args.pd_key, outfile=chaos_file)


            if 'amass' not in skip_tools:
                am_file = output_dir / "amass.txt"
                enum.run_amass(domain, raw_output_dir,outfile=am_file)

            subdomains = enum.load_existing_subdomains(output_dir)
            # Save the final merged subdomains
             # Apply out-of-scope filter
            subdomains = filter_out_of_scope(domain,subdomains,oos_list)
            subdomains_file = output_dir / "subdomains.txt"
            save_to_file(sorted(subdomains),subdomains_file)

            # get subdomain permutations 
            if 'alterx' not in skip_tools:
                alterx_file = output_dir / 'alterx.txt'
                enum.run_alterx(subdomains_file,alterx_file)

            # get alive sub domains
            alive_subdomains_file = output_dir / 'alive_subdomains.txt'
            if 'alterx' not in skip_tools:
                alive.run_dnsx(alterx_file,alive_subdomains_file)
            else:
                alive.run_dnsx(subdomains_file,alive_subdomains_file)

            # read the content of the file
            alive_subdomains = set()
            with open(alive_subdomains_file, 'r') as f:
                alive_subdomains.update(line.strip() for line in f)

            # run naabu to get open ports
            if 'naabu' not in skip_tools:
                naabu_file = output_dir / 'naabu.txt'
                web_scan.run_naabu(alive_subdomains_file,naabu_file,args.rate_limit)

            # run httpx to grep responses from the alive domains
            httpx_file = output_dir / 'httpx.txt'
            alive.run_httpx(alive_subdomains_file,httpx_file)

            # read alive urls 
            if alive_subdomains and 'gowitness' not in skip_tools:
                screenshots.run_gowitness(alive_subdomains_file, output_dir)

            if 'urlfinder' not in skip_tools:
                # run url finder on naabu results
                port_scanned_urls = set()
                if 'naabu' not in skip_tools:
                    hist.run_urlfinder(naabu_file,urlfinder_output_dir)
                else:
                    hist.run_urlfinder(alive_subdomains_file,urlfinder_output_dir)
                
            # fetch historical urls
            if 'waybackurls' not in skip_tools:
                for dom in alive_subdomains:
                    hist.run_waybackurls(dom, wayback_output_dir)
            
            # run katana to fetch content 
            if 'katana' not in skip_tools:
                web_scan.run_katana(alive_subdomains_file,katana_output_dir)


            # check for vulnerabilities using nuclei 
            if 'nuclei' not in skip_tools:
                web_scan.run_nuclei(alive_subdomains_file,raw_output_dir)

        # launch the web dashboard 
        if args.dashboard:
            print(f"{GREEN}[+] Launching the dashboard on port {args.port}, visit {PURPLE}http://localhost:{args.port}/app{GREEN} to access it{RESET}")
            run_command(['python3','-m','http.server',f'{args.port}'])

        print(f"""
============================================================================================================================================
{GREEN}[+] Recon Completed {RESET}
{GREEN}[+] Your output results are in {BLUE}{output_dir}{RESET}
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
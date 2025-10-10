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
        parser.add_argument('-l','--list',action='store_true',help='List of tools used')
        parser.add_argument('-w','--wordlist',default=None,help='Wordlist')
        parser.add_argument('--dashboard',default=True,action='store_true',help='Enable dashboard for the results at http://localhost:8000/app')
        parser.add_argument(
        '--skip-tools',
        help='Comma-separated list of tools to skip (e.g., amass,assetfinder,gowitness)',
        default=''
    )
        args = parser.parse_args()
        
        
        # Get the tools list 
        tools_list = ['assetfinder','subfinder','shuffledns','amass','httprobe','waybackurls','gowitness','nuclei','urlfinder','katana']

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

                # read the content of the file
                with open(af_file, 'r') as f:
                    subdomains.update(line.strip() for line in f)

            if 'subfinder' not in skip_tools:
                sf_file = output_dir / "subfinder.txt"
                enum.run_subfinder(domain, outfile=sf_file)

                # read the content of the file
                with open(sf_file, 'r') as f:
                    subdomains.update(line.strip() for line in f)

            if 'shuffledns' not in skip_tools:
                sdns_file = output_dir / "shuffledns.txt"
                enum.run_shuffledns(domain, data_dir, args.wordlist , outfile=sdns_file)

                # read the content of the file
                with open(sdns_file, 'r') as f:
                    subdomains.update(line.strip() for line in f)

            if 'amass' not in skip_tools:
                am_file = output_dir / "amass.txt"
                enum.run_amass(domain, raw_output_dir,outfile=am_file)

                # read the content of the file
                with open(am_file, 'r') as f:
                    subdomains.update(line.strip() for line in f)

            # Save the final merged subdomains
            subdomains_file = output_dir / "subdomains.txt"
            save_to_file(sorted(subdomains),subdomains_file)

            # get subdomain permutations 
            alterx_file = output_dir / 'alterx.txt'
            enum.run_alterx(subdomains_file,alterx_file)

            # get alive sub domains
            alive_subdomains_file = output_dir / 'alive_subdomains.txt'
            alive.run_dnsx(alterx_file,alive_subdomains_file)

            # read the content of the file
            alive_subdomains = set()
            with open(alive_subdomains_file, 'r') as f:
                alive_subdomains.update(line.strip() for line in f)

             # Apply out-of-scope filter
            alive_subdomains = filter_out_of_scope(alive_subdomains,oos_list)

            # run naabu to get open ports
            naabu_file = output_dir / 'naabu.txt'
            web_scan.run_naabu(alive_subdomains_file,naabu_file)

            # run httpx to grep responses from the alive domains
            httpx_file = output_dir / 'httpx.txt'
            alive.run_httpx(alive_subdomains_file,httpx_file)

            # read alive urls 
            if alive_subdomains and 'gowitness' not in skip_tools:
                screenshots.run_gowitness(alive_subdomains_file, output_dir,http_proto=args.http_proto)

            if 'urlfinder' not in skip_tools:
                # run url finder on naabu results
                port_scanned_urls = set()
                with open(naabu_file, 'r') as file:
                    port_scanned_urls.update(line.strip() for line in f)
                
                for dom in port_scanned_urls:
                    hist.run_urlfinder(dom,urlfinder_output_dir)

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
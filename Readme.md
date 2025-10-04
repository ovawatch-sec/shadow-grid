# Recon Automation Framework - Required Tools

This script performs recon including subdomain enumeration, alive checks, and screenshots. Before using the script, you must manually install the following tools.

## Required Tools

| Tool        | Purpose                         | Installation URL                                                                               |
| ----------- | ------------------------------- | ---------------------------------------------------------------------------------------------- |
| assetfinder | Subdomain enumeration           | [https://github.com/tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder)           |
| subfinder   | Subdomain enumeration           | [https://github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |
| amass       | Subdomain enumeration (passive) | [https://github.com/OWASP/Amass](https://github.com/OWASP/Amass)                               |
| httpx       | Alive subdomain checking        | [https://github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)         |
| gowitness   | Screenshots of alive domains    | [https://github.com/sensepost/gowitness](https://github.com/sensepost/gowitness)               |
| waybackurls | Fetch known URLs from the Wayback Machine | [https://github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) |   

## Installation Notes

1. Ensure you have Go installed (required for some tools).

   * Linux: `sudo apt install golang-go`
   * macOS: `brew install go`
   * Windows: Download from [https://go.dev/dl/](https://go.dev/dl/)

2. Install each tool following the instructions on their respective GitHub pages.

3. Verify installation by running each tool in the terminal. Example:

   ```bash
   assetfinder -h
   subfinder -h
   amass -h
   httpx -h
   gowitness -h
   ```

4. Once all tools are installed, you can run the recon script:

   ```bash
   python recon.py --target example.com
   ```

## Notes

* Make sure your PATH includes the Go binaries if you installed tools using `go install`.
* For any issues, consult the respective tool's GitHub documentation.

def run_assetfinder(domain, outfile=None):
    from core.utils import run_command
    return run_command(["assetfinder", "--subs-only", domain],str(outfile))


def run_subfinder(domain, outfile=None):
    from core.utils import run_command
    return run_command(["subfinder", "-silent", "-d", domain,'-o',str(outfile)])


def run_amass(domain, outfile=None):
    from core.utils import run_command
    return run_command(["amass", "enum", "-passive", "-d", domain,'-o',str(outfile)])

def run_sublist3r(domain, outfile=None):
    from core.utils import run_command
    return run_command(["sublist3r", "-d", domain,'-o',str(outfile)])
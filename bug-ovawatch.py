import argparse
from queue import Queue
import os
import shutil
import sys
import subprocess
import socket
import re
import ipaddress
import threading
import urllib.request
# application class

class AppArg:
    def __init__(self, domain='',file='',threads=5):
        self._domain = domain
        self._file=file
        self._threads=threads

    @property
    def threads(self):
        return self._threads
    @property
    def file(self):
        return self._file
    @property
    def domain(self):
        return self._domain



def create_directories_if_not_exist(*directories):
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)



def create_files_if_not_exist(*files):
    for file_path in files:
        if not os.path.exists(file_path):
            with open(file_path, "w") as file:
                file.write("")  # Write an empty string to the file


RED="\033[1;31m"
BLUE="\033[1;34m"
RESET="\033[0m"
GREEN="\033[1;32m"
PURPLE="\033[1;35m"
ORANGE="\033[1;33m"
PINK="\033[1;35m"


# script banner
def display_banner():
	print(f"""{GREEN}
 █████╗ ██████╗        ██████╗ ██╗   ██╗ █████╗ ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
██╔══██╗██╔══██╗      ██╔═══██╗██║   ██║██╔══██╗██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
███████║██║  ██║█████╗██║   ██║██║   ██║███████║██║ █╗ ██║███████║   ██║   ██║     ███████║
██╔══██║██║  ██║╚════╝██║   ██║╚██╗ ██╔╝██╔══██║██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║  ██║██████╔╝      ╚██████╔╝ ╚████╔╝ ██║  ██║╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═╝╚═════╝        ╚═════╝   ╚═══╝  ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
        {ORANGE}|__ by - {ORANGE}theblxckcicada ({PURPLE}https://ovawatch.co.za{PURPLE}{ORANGE}) __|{GREEN}{RESET}{display_disclaimer()}""")

def display_disclaimer():
     return f"""
           {ORANGE}| {RED}Disclaimer{ORANGE} |                                                                                       |
                        | {RED}Usage of this pentest tool implies understanding and acceptance of potential risks,   {ORANGE}|
                        | {RED}and the user assumes full responsibility for their actions.                           {ORANGE}|
           {RESET}"""

# argument management
def get_parser():
    parser = argparse.ArgumentParser(description='Script description')
    parser.add_argument("-d", "--domain", help="Single domain to scan(e.g google.com)")
    parser.add_argument('-f', '--file', help='Target hosts file')
    parser.add_argument('-t', '--threads',type=int, default=5,  help='Number of threads to use (default = 5)')

    return parser

def get_args(parser):
	    return parser.parse_args()


def args_to_app_args(args):
    return AppArg(**vars(args))

# get arguments
parser = get_parser()
arguments = get_args(parser)
app_args = args_to_app_args(arguments)

# variables
targets = []

def validate_arguments():
    if not app_args.domain and not app_args.file :
        parser.print_help()
        sys.exit(1)

def run_command(message):
    try:
        command = subprocess.Popen(
                        message, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = command.stdout.read() + command.stderr.read()
        return output.decode(encoding='cp1252')
    except Exception as error:
        return error


def save_to_file(destination,results):
    with open(destination,'w') as file:
            file.write(results)
 


def remove_empty_files_and_directories(directory):
    # First pass: Remove empty files
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            if os.path.getsize(filepath) == 0:
                os.remove(filepath)

    # Second pass: Remove empty directories (bottom-up to avoid errors)
    for root, dirs, files in os.walk(directory, topdown=False):
        for dir in dirs:
            dirpath = os.path.join(root, dir)
            if not os.listdir(dirpath):  # directory is now empty
                os.rmdir(dirpath)
    


def remove_duplicate_lines(filename, output_file=None):
    seen = set()
    output_file = output_file or filename  # overwrite input file if no output specified

    with open(filename, 'r') as f:
        lines = f.readlines()

    unique_lines = []
    for line in lines:
        line_strip = line.strip()
        if line_strip not in seen:
            seen.add(line_strip)
            unique_lines.append(line_strip)

    with open(output_file, 'w') as f:
        for line in unique_lines:
            f.write(line + '\n')

# Worker function
def worker():
    while True:
        target = q.get()
        if target is None:
            break
        run_tools(target)
        q.task_done()

# Function to run tools per target
def run_tools(target):
    print(f"[+] Running tools for: {target}")

    commands = [
        f"subfinder -d {target} -o subfinder-{target}.txt",
        f"assetfinder -subs-only {target} > assetfinder-{target}.txt",
        f"sublist3r -d {target} -o sublist3r-{target}.txt"
    ]

    for cmd in commands:
        run_command(cmd)

if __name__ == "__main__":
    display_banner()
    try:
        validate_arguments()

        if app_args.file:
            with open(app_args.file, "r") as f:
                targets.extend([line.strip() for line in f if isinstance(line.strip(),str)])

        if app_args.domain:
            targets.append(app_args.domain)
        
        if not targets:
            print("{RED}[-] No targets specified. Use -d or -f.{RESET}")
            parser.print_help()
            sys.exit(1)

        # Get cleaned targets and remove empty strings
        targets = [item for item in targets if isinstance(item, str)]
        
        # Queue and threads
        q = Queue()
        threads = []

        for _ in range(app_args.threads):
            thread = threading.Thread(target=worker)
            thread.start()
            threads.append(thread)

        # Enqueue targets
        for target in targets:
            q.put(target)

        # Wait for all tasks to be processed
        q.join()

        # Stop threads
        for _ in threads:
            q.put(None)
        for thread in threads:
            thread.join()
    except Exception as e:
        print(f"{RED}[-] {str(e)}{RESET}")

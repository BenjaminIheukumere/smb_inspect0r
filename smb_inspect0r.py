#!/usr/bin/env python3
import sys
import ipaddress
import os
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed
from impacket.smbconnection import SMBConnection
from tqdm import tqdm

threads = 64 # Amount of parallel scans (multithreading n stuff)
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    WHITE   = '\033[37m'
    
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_ascii_art():
    art = r"""
                                                                                                                                                                                                                                           
                    /$$$$$$  /$$      /$$ /$$$$$$$                                      
                   /$$__  $$| $$$    /$$$| $$__  $$                                     
                  | $$  \__/| $$$$  /$$$$| $$  \ $$                                     
                  |  $$$$$$ | $$ $$/$$ $$| $$$$$$$                                      
                   \____  $$| $$  $$$| $$| $$__  $$                                     
                   /$$  \ $$| $$\  $ | $$| $$  \ $$                                     
                  |  $$$$$$/| $$ \/  | $$| $$$$$$$/                                     
                   \______/ |__/     |__/|_______/                                      
 /$$$$$$                                                     /$$      /$$$$$$           
|_  $$_/                                                    | $$     /$$$_  $$          
  | $$   /$$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$   /$$$$$$$ /$$$$$$  | $$$$\ $$  /$$$$$$ 
  | $$  | $$__  $$ /$$_____/ /$$__  $$ /$$__  $$ /$$_____/|_  $$_/  | $$ $$ $$ /$$__  $$
  | $$  | $$  \ $$|  $$$$$$ | $$  \ $$| $$$$$$$$| $$        | $$    | $$\ $$$$| $$  \__/
  | $$  | $$  | $$ \____  $$| $$  | $$| $$_____/| $$        | $$ /$$| $$ \ $$$| $$      
 /$$$$$$| $$  | $$ /$$$$$$$/| $$$$$$$/|  $$$$$$$|  $$$$$$$  |  $$$$/|  $$$$$$/| $$      
|______/|__/  |__/|_______/ | $$____/  \_______/ \_______/   \___/   \______/ |__/      
                            | $$                                                        
                            | $$                                                        
                            |__/                                                        
                                                  
"""
    print(f"{bcolors.OKCYAN}")
    print(art)

def print_imprint():
    imprint = r"""
                         SMB Inspect0r v1.0
                 by Benjamin Iheukumere | SafeLink IT
                    b.iheukumere@safelink-it.com
"""
    print(f"{bcolors.OKBLUE}{imprint}{bcolors.ENDC}")

def scan_host(ip, username=None, password=None):
    shares = []
    try:
        conn = SMBConnection(ip, ip, sess_port=445, timeout=2)
        if username:
            if "\\" in username:
                domain, user = username.split("\\", 1)
            else:
                domain, user = '', username
            conn.login(user, password, domain)
        else:
            conn.login('', '')  # anonymous login
        for share in conn.listShares():
            share_name = share['shi1_netname'][:-1]
            shares.append(share_name)
        conn.logoff()
    except Exception:
        pass
    return ip, shares

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <IP-Range>")
        print(f"Example: {sys.argv[0]} 192.168.1.0/24")
        sys.exit(1)

    # Clear screen and show banner
    clear_screen()
    print_ascii_art()
    print_imprint()
    
    # Ask for username and password
    username = input("Username (empty für anonymous scan): ").strip()
    password = None
    if username:
        password = getpass.getpass("Passwort: ")

    network = ipaddress.ip_network(sys.argv[1], strict=False)
    hosts = list(network.hosts())

    prefix = username if username else "anon"
    output_file = f"{prefix}_smb_shares_found.txt"

    print(f"Results will be saved in: {bcolors.BOLD}{output_file}{bcolors.ENDC}\n")
    print(f"{bcolors.OKGREEN}\nStarting Network-Scan {sys.argv[1]} with User: {username or 'anonym'}")
    
    results = []
    block_size = 30
    print(f"{bcolors.OKCYAN}")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        for i in range(0, len(hosts), block_size):
            start_ip = hosts[i]
            end_ip = hosts[min(i + block_size - 1, len(hosts)-1)]
            #print(f"{bcolors.OKCYAN}Checking IPs: {start_ip} - {end_ip}{bcolors.ENDC}") #uncomment, if you wnat to print the found shares while the scan is still running
            for ip in hosts[i:i+block_size]:
                futures[executor.submit(scan_host, str(ip), username, password)] = ip

        with tqdm(total=len(hosts), desc="Scanning", unit="host") as pbar:
            for future in as_completed(futures):
                ip, shares = future.result()
                if shares:
                    results.append((ip, shares))
                pbar.update(1)

    with open(output_file, "w") as f:
        for ip, shares in results:
            f.write(f"{ip} - Shares: {', '.join(shares)}\n")

    print(f"\n{bcolors.OKGREEN}Scan finished!{bcolors.ENDC}")
    print("\n\n")
    print(f"\n{bcolors.BOLD}Results:{bcolors.ENDC}")
    if output_file and os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        with open(output_file, 'r') as f:
            print(f.read())
    else:
        print("No shares found ¯\_(ツ)_/¯")
if __name__ == "__main__":
    main()


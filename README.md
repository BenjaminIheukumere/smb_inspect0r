# SMB Inspect0r
SMB Inspect0r is a fast multithreaded Python tool to scan networks for accessible SMB shares, supporting both anonymous and authenticated logins. Features include progress tracking, and detailed output of discovered shares.

## Requirements
Tested on Kali 2025.2
Needs Impacket: sudo apt install python3-impacket

## Installation
1. git clone https://github.com/BenjaminIheukumere/smb_inspect0r.git
2. cd smb_inspect0r
3. chmod +x smb_inspect0r

## Usage
./smb_inspect0r.py <IP-Range> or python3 smb_inspect0r.py <IP-Range>
Enter Username & Password for authenticated scan.
Leave Username empty (just press enter) for anonymous scan.

### Examples
Single IP: ./smb_inspect0r 10.10.10.10
IP-Range: ./smb_inspect0r 10.10.10.0/24

## Output
Authenticated Scan: Found shares will be put in #USERNAME#_smb_shares_found.txt
Unauthenticated Scan: Found shares will be put in anon_smb_shares_found.txt

Content of the output file will be printed on screen, when scan is done, too, if shares were found.

## Screenshot of SMB Inspect0r in action


## Tuning
Modify "threads" variable in the top of the script (after the imports) to change the number of parallel threads.

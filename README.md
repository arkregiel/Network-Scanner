# Python Network Scanner

Live host (in LAN) discovery, their IPv4 and MAC addresses and open TCP ports

This is proof of concept, it's not optimized

## Install requirements

```
$ pip install -r requirements.txt
```

## Usage

```
usage: netscan.py [-h] [-p PORT1,PORT2,...] [-r] [-s] [--noverbose] IP/PREFIX_LENGTH

Network Scanner - discovering live hosts and their open ports

positional arguments:
  IP/PREFIX_LENGTH      Network to scan in CIDR format (or single IPv4 address)

optional arguments:
  -h, --help            show this help message and exit
  -p PORT1,PORT2,..., --ports PORT1,PORT2,...
                        Port numbers (comma separated). If you want to scan range, use -r/--range
  -r, --range           Scan port range. If enabled, -p/--ports option should take arguments like this: FIRST-LAST
  -s, --syn             Use SYN scan
  --noverbose           Disable verbosing

examples:
$ python netscan.py -p 22,53,80,443 --syn 192.168.1.0/24
$ python netscan.py -p 1-1000 --range --syn 192.168.1.0/24
```

Remember to have the `oui.txt` file in the same directory as the script.

## Example output

```
Scanning...
(It may take some time)
.............................................................................................
<output omitted>
.................................................
--------
Results:

Scanned IP: 192.168.1.1
MAC: aa:bb:cc:dd:ee:ff (Organization X)
Open TCP ports:
(80, 443)
-------------------------
Scanned IP: 192.168.1.19
MAC: 11:22:33:44:55:66 (Organization Y)
Open TCP ports:
(80,)
-------------------------
Scanned IP: 192.168.1.22
MAC: ff:ee:dd:cc:bb:aa (Organization Z)
Open TCP ports:
()
-------------------------
```
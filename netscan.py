from typing import Iterable
from netaddr import IPNetwork
from scapy.all import srp, sr1, Ether, IP, TCP, ARP, RandShort
import socket, argparse, threading, sys


class ScannedHost:
    ip = None
    mac = None
    organization = 'Unknown'  # based on OUI
    open_ports = (None)

    def __init__(self, ip_addr: str, mac: str=None) -> None:
        self.ip = ip_addr
        self.mac = mac

    def __str__(self) -> str:
        s = f'Scanned IP: {self.ip}\n'
        s += f'MAC: {self.mac} ({self.organization})\n'
        s += 'Open TCP ports:\n'
        s += f'{self.open_ports}\n'
        s += '-' * 25
        return s


class NetworkScanner:
    scanned_hosts = []
    syn = False
    network = None
    ports = None
    is_range = True
    verbose = True
    ouis = {}

    def __init__(self) -> None:
        """Initializes object and loads 'oui.txt' file"""
        # OUI values taken from https://standards-oui.ieee.org/
        self.load_ouis('oui.txt')

    def load_ouis(self, filename: str) -> None:
        """Loads 'oui.txt' file data to memory"""
        try:
            fh = open(filename)
            for line in fh:
                oui, organization = line.rstrip().split('|')
                self.ouis[oui] = organization
        except OSError as e:
            print("ERROR: Cannot load OUI file")
            print(e)

    def oui_lookup(self, mac: str) -> str:
        """Looks up an organization that is assigned to OUI of MAC address"""
        oui = mac[:8]
        organization = self.ouis.get(oui)
        if organization is None:
            return 'Unknown'
        return organization

    def check_port_status(self, host_ip: str, port_number: int) -> bool:
        """Checks if TCP port is open"""
        if self.syn:    # SYN scan
            syn_packet = IP(dst=host_ip) / TCP(sport=RandShort(), dport=port_number, flags='S')
            resp = sr1(syn_packet, timeout=3, verbose=False)
            if resp is not None:
                if str(resp[TCP].flags).upper() == 'SA':
                    return True
            return False
        else:   # Full three-way handshake
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((host_ip, port_number))
                return True
            except socket.error:
                return False

    def __scan_port_thread(self, host_ip: str, port: int, out_open_ports: list) -> None:
        if self.verbose:
            print('.', end='')
        else:
            sys.stdout.write('')
        sys.stdout.flush()
        if self.check_port_status(host_ip, port):
                out_open_ports.append(port)

    def scan_tcp_ports(self, host_ip: str) -> tuple:
        """Looks for open ports on the host"""
        open_ports = []
        if self.is_range:
            ports = (port for port in range(self.ports[0], self.ports[1] + 1))
        else:
            ports = self.ports
        
        threads = []
        for port in ports:
            t = threading.Thread(target=self.__scan_port_thread, args=[host_ip, port, open_ports])
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
            threads.remove(t)
            
        return tuple(sorted(open_ports))

    def is_alive(self, host_ip: str) -> str:
        """Checks if host is online with ARP request"""
        arp_request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op='who-has', pdst=host_ip)
        resp, _ = srp(arp_request, timeout=2, retry=10, verbose=False)
        for _, r in resp:
            return r[Ether].src # if host is alive, return its MAC address
        return None

    def scan_host(self, host_ip: str) -> ScannedHost:
        if self.verbose:
            print(f"Checking IP: {host_ip}")
            sys.stdout.flush()
        if (mac := self.is_alive(host_ip)) is not None:
            host = ScannedHost(host_ip, mac=mac)
            host.organization = self.oui_lookup(host.mac)
            host.open_ports = self.scan_tcp_ports(host.ip)
            return host
        else:
            return None

    def __scan_host_thread(self, host_ip: str, out_alive_hosts: list) -> None:
        if (host := self.scan_host(host_ip)) is not None:
            out_alive_hosts.append(host)
        if self.verbose:
            print('.', end='')
            sys.stdout.flush()
        return

    def scan(self, cidr: str, ports: tuple=(1, 1000), is_range: bool=True,
                 tcp_syn_only: bool=False, verbose: bool=True) -> Iterable:
        self.ports = ports
        self.is_range = is_range
        self.syn = tcp_syn_only
        self.network = IPNetwork(cidr)
        self.verbose = verbose

        alive_hosts = []
        threads = []
        if self.verbose:
            print('Scanning...')
            print('(It may take some time)')
            sys.stdout.flush()
        for addr in self.network.iter_hosts():
            addr = str(addr)
            t = threading.Thread(target=self.__scan_host_thread, args=[addr, alive_hosts])
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
            threads.remove(t)
        if self.verbose:
            print()
            sys.stdout.flush()
        for host in alive_hosts:
            yield host


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Network Scanner - discovering live hosts and their open ports",
        epilog=f"examples:\n$ python {sys.argv[0]} -p 22,53,80,443 --syn 192.168.1.0/24\n" +
        f"$ python {sys.argv[0]} -p 1-1000 --range --syn 192.168.1.0/24\n",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        'network',
        help="Network to scan in CIDR format (or single IPv4 address)",
        metavar="IP/PREFIX_LENGTH"
    )
    parser.add_argument(
        '-p', '--ports',
        metavar="PORT1,PORT2,...",
        help="Port numbers (comma separated). If you want to scan range, use -r/--range",
        default="21,22,23,53,80,443"
    )
    parser.add_argument(
        '-r', '--range',
        action='store_true',
        default=False,
        help="Scan port range. If enabled, -p/--ports option should take arguments like this: FIRST-LAST"
    )
    parser.add_argument('-s', '--syn', action='store_true', help="Use SYN scan", default=False)
    parser.add_argument('--noverbose', action='store_false', help="Disable verbosing", default=True)
    args = parser.parse_args(sys.argv[1:])

    if args.range:
        first_port, last_port = tuple(map(int, args.ports.split('-')))
        ports = (first_port, last_port)
    else:
        ports = tuple(map(int, args.ports.split(',')))

    print('Network Scanner')
    print('-' * 15)

    print("Summary:")
    print(f"Network: {args.network}")
    print(f"Ports: {ports}")
    print(f"Scanning range? - {'Yes' if args.range else 'No'}")
    print(f"SYN scan? - {'Yes' if args.syn else 'No'}")
    print('-' * 25)

    scanner = NetworkScanner()

    hosts = sorted(
        (
            host for host in scanner.scan(
                args.network,
                ports=ports,
                is_range=args.range,
                tcp_syn_only=args.syn,
                verbose=args.noverbose
            )
        ),
        key=lambda h: h.ip
    )

    print('-' * 8 + "\nResults:\n")
    for host in hosts:
        print(host)

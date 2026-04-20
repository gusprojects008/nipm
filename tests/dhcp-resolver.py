#!/usr/bin/env python3

import sys
import subprocess
import argparse
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, RandInt, sendp, sniff

def handle_dhcp_packets(packet):
    try:
        if packet.haslayer(BOOTP) and packet.haslayer(DHCP):
            is_offer = False
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == 'message-type' and opt[1] == 2:
                    is_offer = True
                    break
            
            if not is_offer:
                return None

            address_gateway = packet[IP].src
            address_offered = packet[BOOTP].yiaddr
            subnet_mask = None
            server_id = None

            for opt in packet[DHCP].options:
                if isinstance(opt, tuple):
                    if opt[0] == 'subnet_mask':
                        subnet_mask = opt[1]
                    elif opt[0] == 'server_id':
                        server_id = opt[1]

            if subnet_mask:
                return {
                    "ip": address_offered,
                    "router": address_gateway,
                    "subnet": subnet_mask,
                    "server": server_id or address_gateway
                }
    except Exception as error:
        raise RuntimeError(f"Error processing DHCP response: {error}")

def get_dhcp_config(iface: str, requested_address: str = "0.0.0.0"):
    xid = RandInt()
    mac = open(f"/sys/class/net/{iface}/address").read().strip()
    dhcp_options = [('message-type', 'discover'), ('requested_addr', requested_address), # very important
                   ('subnet_mask', '0.0.0.0'), 'end', ('pad', b'\x00')]
    discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=bytes.fromhex(mac.replace(":", "")), xid=xid, flags=0x8000) / # op=1 == dhcp_request, op=2 == dhcp_reply
        DHCP(options=dhcp_options)
    )

    print(f"[+] Sending DHCP Discover on {iface}...")
    sendp(discover, iface=iface, verbose=0)
    
    result = []
    def capture_handler(pkt):
        cfg = handle_dhcp_packets(pkt)
        if cfg:
            result.append(cfg)
    
    print("[+] Capturing DHCP response...")
    sniff(filter="udp and (port 67 or port 68)", iface=iface, timeout=10, store=False, prn=capture_handler)
    
    if not result:
        raise RuntimeError("No DHCP Offer received")
    
    return result[0]

def apply_ip_config(iface: str, ip: str, mask: str, gateway: str = None):
    subnet_mask_split = mask.split('.')
    subnet_mask_bin = [(bin(int(octet))[2:].zfill(8)) for octet in subnet_mask_split]
    subnet_mask_join_bin = ''.join(subnet_mask_bin)
    cidr_value = subnet_mask_join_bin.count('1')
    
    print(f"[+] Applying {ip}/{cidr_value} to {iface}")
    subprocess.run(["ip", "addr", "flush", "dev", iface], check=False)
    subprocess.run(["ip", "addr", "add", f"{ip}/{cidr_value}", "dev", iface], check=True)
    subprocess.run(["ip", "link", "set", iface, "up"], check=True)
    if gateway:
        print(f"[+] Adding default route via {gateway}")
        subprocess.run(["ip", "route", "add", "default", "via", gateway], check=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simple command line utilities to request a specific IP address from the DHCP server."
    )
    parser.add_argument("--ifname", type=str, required=True, help="Interface name")
    parser.add_argument("--request-address", type=str, help="Request specific IP address from DHCP server")
    args = parser.parse_args()

    iface = args.ifname
    requested_address = args.request_address
    try:
        if requested_address:
            print(f"[+] Requesting IP {args.request_address} from DHCP server...")
        cfg = get_dhcp_config(iface, requested_address)
        print(f"[+] Configuration received: {cfg}")
        if not cfg.get("subnet"):
            raise RuntimeError("No subnet mask received from DHCP server")
        apply_ip_config(iface, cfg["ip"], cfg["subnet"], cfg.get("router"))
        print("[+] IP configuration applied successfully")
    except Exception as error:
        print(f"[-] Error: {error}")
        sys.exit(1)


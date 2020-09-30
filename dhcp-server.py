from scapy.all import *
from enum import Enum
import ipaddress
import binascii
import time

devices = []
leases = []

iface = None
server_ip = None
server_mac = None
gateway_ip = server_ip
subnet_mask = "255.255.255.0"

store_leases_for = 120 # 2 minutes

broadcast_ip = "255.255.255.255"
broadcast_mac = "ff:ff:ff:ff:ff:ff"

starting_ip = ipaddress.IPv4Address("192.168.0.2")
ending_ip = ipaddress.IPv4Address("192.168.0.254")
ip_network = ipaddress.ip_network("192.168.0.0/24")

class DHCPType(Enum):
    
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    ACK = 5
    INFORM = 8

class Lease:

    def __init__(self, device, ip, expires=None):
        self.device = device
        self.ip = ip
        self.expires = expires

class Device:

    def __init__(self, mac):
        self.mac = mac

def new_lease(device, ip, expires=None, ack=False):
    lease = Lease(device, ip, expires, ack)
    leases.add(lease)

def get_lease_by_ip(ip):
    for lease in leases:
        if lease.ip == ip:
            return lease

def get_lease_by_device(device):
    for lease in leases:
        if lease.device == device:
            return lease

def free_lease(lease):
    leases.remove(lease)

def get_device(mac):

    for device in devices:
        if device.mac == mac:
            return device

def new_device(mac):

    device = Device(mac)
    devices.append(device)

    print("New device found (" + device.mac + ")")

def handle_dhcp_packet(packet):

    device = get_device(packet.src)

    if device is None and not packet.src == server_mac:
        device = new_device(packet.src)

    dhcp_type = get_dhcp_type(packet)

    reply = create_dhcp_reply(packet)
    
    if dhcp_type == DHCPType.DISCOVER:

        lease = get_lease_by_device(device)

        if lease is None:
        
            for ip_int in range(int(starting_ip), int(ending_ip)):
                
                lease = get_lease_by_ip(ipaddress.IPv4Address(ip_int))
                
                if lease is None:
                    lease = new_lease(device, ipaddress.IPv4Address(ip_int))
                    offer_ip(reply, lease.ip)
                    print("Offered " + lease.ip + " to " + packet.src)
                    break
                
                elif lease.expires is not None and lease.expires + store_leases_for < time.time():
                    # Lease exists but has expired so should be used up
                    free_lease(lease)
                    lease = new_lease(device, ipaddress.IPv4Address(ip_int))
                    offer_ip(reply, lease.ip)
                    print("Offered " + lease.ip + " to " + packet.src + " (IP previously belonged to this device)")
                    break

            print("Failed to create a provisional lease for " + device.mac)
            print("This may be because there are no free IP addresses")
            exit()

        else:

            # Lease exists and has not expired, re-offer IP
            offer_ip(reply, lease.ip)
            print("Offered " + lease.ip + " to " + packet.src)

    elif dhcp_type == DHCPType.REQUEST:
        
        requested_ip = get_dhcp_option(packet, 'requested_addr')

        print("Received request from " + packet.src + " for " + requested_ip)

        if not ipaddress.ip_address(requested_ip) in ip_network:
            nak_request(reply)
            print("Rejected request from " + packet.src + " for " + requested_ip + " because it is not in the current subnet")
            return 

        lease = get_lease_by_ip(requested_ip)
        if lease is None or lease.mac == device.mac:
            ack_request(reply, requested_ip)
            print("Accepted request from " + packet.src + " for " + requested_ip)
        else:
            nak_request(reply)
            print("Rejected request from " + packet.src + " for " + requested_ip + " because that lease is taken by another device")

def get_dhcp_option(packet, opt):
    options = packet[DHCP].options
    for option in options:
        if option[0] == opt:
            return option[1]

def get_dhcp_type(packet):

    for dhcp_type in DHCPType:
        if packet[DHCP].options[0][1] == dhcp_type.value:
            return dhcp_type

def create_dhcp_reply(packet):
    
    ether = Ether(src=server_mac, dst=broadcast_mac)
    ip = IP(src=server_ip, dst=broadcast_ip)
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, siaddr=server_ip, giaddr=gateway_ip, chaddr=binascii.unhexlify(packet[Ether].src.replace(':', '')), xid=packet[BOOTP].xid)
    dhcp = DHCP(options=[])

    return ether/ip/udp/bootp/dhcp

def offer_ip(packet, client_ip):
    
    packet[BOOTP].yiaddr = client_ip

    packet[DHCP].options = [('message-type', 'offer'), ('subnet_mask', subnet_mask), ('server_id', server_ip), ('end')]
    
    sendp(packet, iface=iface, verbose=False)

def ack_request(packet, client_ip):

    packet[BOOTP].yiaddr = client_ip

    packet[DHCP].options = [('message-type', 'ack'), ('end')]

    sendp(packet, iface=iface, verbose=False)

def nak_request(packet):

    packet[DHCP].options = [('message-type', 'nak'), ('end')]

    sendp(packet, iface=iface, verbose=False)

IFACES.show()
interface_id = int(input("Which interface should the DHCP server run on? (enter index): "))
iface = IFACES.dev_from_index(interface_id)
server_ip = get_if_addr(iface)
server_mac = get_if_hwaddr(iface)

print("\nListening for DHCP activity\n")

sniff(iface=iface, filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)

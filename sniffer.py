import socket
import struct
import textwrap

# --- Helper Functions ---

def get_mac_addr(bytes_addr):
    """Formats a MAC address from bytes to human-readable string (AA:BB:CC...)."""
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def get_ipv4(addr):
    """Formats an IP address from bytes to string (192.168.1.1)."""
    return '.'.join(map(str, addr))

# --- Main Sniffer Loop ---

def main():
    # 1. Create a raw socket (Linux specific)
    # AF_PACKET: Low level interface to packet sockets
    # SOCK_RAW: Access to raw IP packets
    # ntohs(3): Capture everything (ETH_P_ALL)
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("Sniffer started... Waiting for packets.")

    while True:
        # 2. Receive data
        # 65535 is the buffer size (max packet size)
        raw_data, addr = conn.recvfrom(65535)

        # 3. Parse Ethernet Header (First 14 bytes)
        dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', raw_data[:14])
        
        # Convert protocol to host byte order to check for IPv4 (0x0800 = 8)
        eth_proto = socket.htons(eth_proto)

        print('\n' + '-'*50)
        print(f"Ethernet Frame:")
        print(f"Destination: {get_mac_addr(dest_mac)}, Source: {get_mac_addr(src_mac)}, Protocol: {eth_proto}")

        # 4. If Protocol is 8 (IPv4), Parse IP Header
        if eth_proto == 8:
            # IP Header is after the first 14 bytes
            version_header_length = raw_data[14]
            # Bitwise operation to get the header length (bottom 4 bits)
            header_length = (version_header_length & 15) * 4
            
            # Unpack the IP header
            # B=1 byte, H=2 bytes, 4s=4 bytes string
            ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[14:14+20])
            
            src_ip = get_ipv4(src)
            target_ip = get_ipv4(target)

            print(f"\tIPv4 Packet:")
            print(f"\t\tVersion: {version_header_length >> 4}, Header Length: {header_length}, TTL: {ttl}")
            print(f"\t\tProtocol: {proto}, Source: {src_ip}, Target: {target_ip}")
            
            # 5. Handle inner protocols (TCP/UDP/ICMP)
            # Data starts after Ethernet Header (14) + IP Header (variable, usually 20)
            data_offset = 14 + header_length
            
            # TCP (Protocol 6)
            if proto == 6:
                print("\t\tProtocol: TCP")
            # UDP (Protocol 17)
            elif proto == 17:
                print("\t\tProtocol: UDP")
            # ICMP (Protocol 1)
            elif proto == 1:
                print("\t\tProtocol: ICMP")

if __name__ == "__main__":
    main()

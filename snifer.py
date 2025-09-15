# Packet Sniffer in Python
# Author: Dev setpal
# Description: Captures IP packets using raw sockets and logs source/destination info with timestamps.

import socket   # Allows low-level network communication. 
import struct   # Handles binary data conversion. 
from datetime import datetime # Provides timestamps.

# Function to parse the IP header from raw packet data
def parse_ip_header(data):
    # Unpack the first 20 bytes of the IP header using network byte order
    unpacked = struct.unpack('!BBHHHBBH4s4s', data[:20])
    # Convert source and destination IP addresses from binary to readable format
    src_ip = socket.inet_ntoa(unpacked[8])
    dst_ip = socket.inet_ntoa(unpacked[9])
    return src_ip, dst_ip

def main():
    # Create a raw socket to capture all IP packets
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # Bind the socket to your local IP address (replace with your actual IP)
    sniffer.bind(("YOUR_IP_ADDRESS", 0))

    # Include IP headers in the captured packets
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode to capture all packets (Windows only)
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print("[*] Packet sniffer started...\n")

    try:   # Handles errors and interruptions gracefully.

        while True:  # Continuously listen for incoming packets.

            # Receive a packet (max size 65565 bytes)
            raw_data, addr = sniffer.recvfrom(65565)

            # Parse source and destination IP addresses from the packet
            src, dst = parse_ip_header(raw_data)

            # Get current timestamp for logging
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Print packet info with timestamp
            print(f"[{timestamp}] {src} -> {dst} | {len(raw_data)} bytes")

    except KeyboardInterrupt:
        # Disable promiscuous mode before exiting (Windows only)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("\n[*] Sniffer stopped.")

# Entry point of the script
if __name__ == "__main__":
    main()

    ''' If you're on Linux, replace:
        socket.AF_INET → socket.AF_PACKET
        socket.IPPROTO_IP → socket.ntohs(0x0003)
        And remove the ioctl lines—they're Windows-specific
        Also, bind to ("",0) to capture all interfaces. ''' 

   
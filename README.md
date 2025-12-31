# 🐍 Python Raw Socket Packet Sniffer

A low-level network packet sniffer built from scratch in Python. 

This tool captures raw binary data from the network interface card (NIC), bypasses the OS network stack, and manually parses Ethernet frames and IPv4 headers using bitwise operations and structure unpacking.

## ⚠️ Disclaimer
**Educational Use Only:** This tool is intended for learning how network protocols (TCP/IP) work at a binary level. Unauthorised packet sniffing is illegal. Only run this on networks you own or have explicit permission to monitor.

## 🚀 Features
* **Raw Socket Implementation:** Uses `socket.AF_PACKET` to access Layer 2 data.
* **Protocol Decoding:**
    * **Layer 2:** Ethernet II Frames (Destination MAC, Source MAC, Protocol).
    * **Layer 3:** IPv4 Packets (Version, Header Length, TTL, Protocol, Source/Target IP).
* **Hex Conversion:** Manually formats MAC addresses and IP strings from raw bytes.

## 🛠️ How It Works (The Technical Part)

### 1. The Ethernet Frame
The script first captures the raw frame and unpacks the first 14 bytes (The Ethernet Header).

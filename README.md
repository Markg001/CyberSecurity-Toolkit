# Cybersecurity Toolkit

A Python-based **Cybersecurity Toolkit** designed for performing network-related tasks. This toolkit includes tools such as:

- **MAC Address Changer**: Modify the MAC address of a network interface.
- **ARP Poisoning**: Spoof ARP packets to intercept or redirect traffic.
- **Packet Sniffer**: Capture HTTP requests and extract login information from network packets.

---

## **Features**

### 1. MAC Address Changer
- Change the MAC address of a network interface to either a random or a custom MAC address.
- Helps in bypassing MAC-based filters or enhancing privacy.

### 2. ARP Poisoning
- Spoof ARP packets to perform a man-in-the-middle attack.
- Redirect traffic between the target machine and the gateway for packet inspection or interception.

### 3. Packet Sniffer
- Capture network packets in real-time.
- Extract sensitive information such as login credentials from HTTP requests.

### 4. DNS Spoofer**: 
- Intercept and redirect DNS queries to a malicious server.
### 5. DHCP Exhaustion**: 
- Perform DHCP starvation attacks to exhaust available IPs.

---

## **Requirements**

1. **Python Version**: Python 3.x
2. **Required Python Libraries**:
   - `scapy`: For packet manipulation and network sniffing.
   - `netfilterqueue`: To interact with Linux networking layers.
   - `Pillow`: For GUI images and `tkinter` integration.
   - `tkinter`: For creating the graphical user interface (GUI).

> **Note**: Run the toolkit in **privileged mode** (e.g., `sudo` in Linux) for proper functionality.

---

## **Project Overview**

### Toolkit Interface
![Project picture](https://github.com/user-attachments/assets/7e04eddd-af6c-4d0d-bf23-b374240c2eec)

After starting the toolkit, you will see various options, including **MAC Address Changer**, **ARP Poisoning**, and **Packet Sniffer**:

### 1. MAC Address Changer
![mac_changer](https://github.com/user-attachments/assets/aedcdbd8-2ba0-4371-9fad-70f473af556f)

- Modify the MAC address of your network interface with ease.

### 2. ARP Poisoning
![Arp_Poisoning](https://github.com/user-attachments/assets/9272342e-20b5-49de-9262-6a35a50a37be)

- Execute ARP spoofing to redirect traffic and perform man-in-the-middle attacks.

### 3. Packet Sniffer
![Packet_sniffer](https://github.com/user-attachments/assets/71b25255-fa28-4a6e-ab28-11faa83fbabd)

- Sniff packets from the network and extract critical information such as URLs and login credentials.

---

## **Planned Features**

- **DNS Spoofer**: Intercept and redirect DNS queries to a malicious server.
- **DHCP Exhaustion**: Perform DHCP starvation attacks to exhaust available IPs.

---

> This toolkit is meant for educational purposes only. Use responsibly and ensure compliance with applicable laws and regulations.

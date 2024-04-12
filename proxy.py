import socket
import select
import random
import sys
import time

# Proxy configuration
PROXY_IP = "127.0.0.1"
PROXY_PORT = 8888

# Server configuration
SERVER_IP = "127.0.0.1"
SERVER_PORT = 8889

# Probability of dropping packets from client and server
DROP_CLIENT_PACKET_PROBABILITY = 0.2
DROP_SERVER_PACKET_PROBABILITY = 0.2

# Probability of delaying packets from client and server
DELAY_CLIENT_PACKET_PROBABILITY = 0.2
DELAY_SERVER_PACKET_PROBABILITY = 0.2

# Delay range in milliseconds for packets from client and server
CLIENT_DELAY_RANGE = (4000, 8000)  # (min, max)
SERVER_DELAY_RANGE = (4000, 8000)  # (min, max)

# Flags to enable or disable packet dropping and delaying
PACKET_DROPPING_ENABLED = True
PACKET_DELAYING_ENABLED = True


def should_drop_packet(probability):
    return PACKET_DROPPING_ENABLED and random.random() < probability


def should_delay_packet(probability):
    return PACKET_DELAYING_ENABLED and random.random() < probability


def delay_packet(packet_type):
    min_delay, max_delay = CLIENT_DELAY_RANGE if packet_type == "client" else SERVER_DELAY_RANGE
    delay = random.randint(min_delay, max_delay) / 1000
    time.sleep(delay)
    print(f"Delayed {packet_type} packet for {delay} seconds")


def handle_client_to_server(client_data, server_socket):
    if should_drop_packet(DROP_CLIENT_PACKET_PROBABILITY):
        print("Dropped packet from client")
        return

    if should_delay_packet(DELAY_CLIENT_PACKET_PROBABILITY):
        delay_packet("client")

    server_socket.sendto(client_data, (SERVER_IP, SERVER_PORT))


def handle_server_to_client(proxy_socket, client_addr, server_data):
    if should_drop_packet(DROP_SERVER_PACKET_PROBABILITY):
        print("Dropped packet from server")
        return

    if should_delay_packet(DELAY_SERVER_PACKET_PROBABILITY):
        delay_packet("server")

    proxy_socket.sendto(server_data, client_addr)


def main():
    global server_socket

    # Create proxy socket
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    proxy_socket.bind((PROXY_IP, PROXY_PORT))

    print("Proxy is listening...")

    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        while True:
            # Listen for packets from both client and server simultaneously
            ready_sockets, _, _ = select.select([proxy_socket, server_socket], [], [])

            for ready_socket in ready_sockets:
                if ready_socket == proxy_socket:
                    # Packet received from client
                    client_data, client_addr = proxy_socket.recvfrom(1024)
                    print(f"Received data from client: {client_data}")

                    # Forward packet to server
                    handle_client_to_server(client_data, server_socket)

                elif ready_socket == server_socket:
                    # Packet received from server
                    server_data, server_addr = server_socket.recvfrom(1024)
                    print(f"Received data from server: {server_data}")

                    # Forward packet to client
                    handle_server_to_client(proxy_socket, client_addr, server_data)
                    print(f"Proxy sent to client: {server_data}")

    except KeyboardInterrupt:
        print("Proxy shutting down...")
    finally:
        proxy_socket.close()
        server_socket.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--disable-dropping":
        PACKET_DROPPING_ENABLED = False
    if len(sys.argv) > 1 and sys.argv[2] == "--disable-delay":
        PACKET_DELAYING_ENABLED = False
    main()

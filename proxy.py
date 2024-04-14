import socket
import select
import random
import sys
import time
import matplotlib.pyplot as plt
import threading
import datetime

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
CLIENT_DELAY_RANGE = (1000, 4000)  # (min, max)
SERVER_DELAY_RANGE = (1000, 4000)  # (min, max)

# Flags to enable or disable packet dropping, delaying, and graphing
PACKET_DROPPING_ENABLED = True
PACKET_DELAYING_ENABLED = True
GRAPH_ENABLED = True

# Lists to store data for plotting
client_packets = []
server_packets = []
time_points = []
client_times = []
server_times = []

# Function to update the plot
def update_plot():
    while True:
        time.sleep(1)
        if GRAPH_ENABLED:
            time_points.append(datetime.datetime.now())
            client_packets.append(sum(1 for t in client_times if t > time_points[-1] - datetime.timedelta(seconds=1)))
            server_packets.append(sum(1 for t in server_times if t > time_points[-1] - datetime.timedelta(seconds=1)))
            plt.clf()  # Clear the current plot
            plt.plot(time_points, client_packets, label='Client Packets')
            plt.plot(time_points, server_packets, label='Server Packets')
            plt.xlabel('Time')
            plt.ylabel('Packets')
            plt.legend()
            plt.pause(0.01)

# Thread to update the plot
plot_thread = threading.Thread(target=update_plot)
plot_thread.daemon = True
plot_thread.start()

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
    client_times.append(datetime.datetime.now()) 

def handle_server_to_client(proxy_socket, client_addr, server_data):
    if should_drop_packet(DROP_SERVER_PACKET_PROBABILITY):
        print("Dropped packet from server")
        return

    if should_delay_packet(DELAY_SERVER_PACKET_PROBABILITY):
        delay_packet("server")

    proxy_socket.sendto(server_data, client_addr)
    server_times.append(datetime.datetime.now())

def send_packet(socket, packet, address):
    socket.sendto(packet.encode(), address)

def is_handshake_packet(data):
    return data.startswith(b"SYN") or data.startswith(b"SHAKE_ACK") or data.startswith(b"SYN-ACK") or data.startswith(
        b"FIN") or data.startswith(b"FIN-ACK")

def handle_handshake_packet(packet, socket, address):
    socket.sendto(packet, address)
    print(f"Forwarded handshake packet to {address}: {packet}")

def main():

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
                    if is_handshake_packet(client_data):
                        handle_handshake_packet(client_data, server_socket, (SERVER_IP, SERVER_PORT))
                    else:
                        handle_client_to_server(client_data, server_socket)

                elif ready_socket == server_socket:
                    # Packet received from server
                    server_data, server_addr = server_socket.recvfrom(1024)
                    print(f"Received data from server: {server_data}")

                    # Forward packet to client
                    if is_handshake_packet(server_data):
                        handle_handshake_packet(server_data, proxy_socket, client_addr)
                    else:
                        handle_server_to_client(proxy_socket, client_addr, server_data)
                        print(f"Proxy sent to client: {server_data}")

    except KeyboardInterrupt:
        print("Proxy shutting down...")
    finally:
        proxy_socket.close()
        server_socket.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if "--disable-dropping" in sys.argv:
            PACKET_DROPPING_ENABLED = False
            sys.argv.remove("--disable-dropping")

        if "--disable-delay" in sys.argv:
            PACKET_DELAYING_ENABLED = False
            sys.argv.remove("--disable-delay")

        if "--disable-graph" in sys.argv:
            GRAPH_ENABLED = False
            sys.argv.remove("--disable-graph")

    main()

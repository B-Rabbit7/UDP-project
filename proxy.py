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
DROP_CLIENT_PACKET_PROBABILITY = 0.1
DROP_SERVER_PACKET_PROBABILITY = 0.2

# Probability of delaying packets from client and server
DELAY_CLIENT_PACKET_PROBABILITY = 0.2
DELAY_SERVER_PACKET_PROBABILITY = 0.2

# Delay range in milliseconds for packets from client and server (min, max)
CLIENT_DELAY_RANGE = (1000, 4000)
SERVER_DELAY_RANGE = (1000, 4000)

# Flags to enable or disable packet dropping, delaying, and graphing
PACKET_DROPPING_ENABLED = True
PACKET_DELAYING_ENABLED = True
GRAPH_ENABLED = True

# Lists to store data for plotting
client_sent_packets = []
server_sent_packets = []
client_received_packets = []
server_received_packets = []
time_points = []
client_sent_times = []
server_sent_times = []
client_received_times = []
server_received_times = []


def update_plot():
    seconds_counter = 1  # Initialize the counter for seconds
    while True:
        time.sleep(1)
        if GRAPH_ENABLED:
            current_time = datetime.datetime.now()
            # Calculate the number of packets sent and received by the client and server in the last second
            client_sent_count = sum(
                1 for sent_time in client_sent_times if sent_time > current_time - datetime.timedelta(seconds=1))
            server_sent_count = sum(
                1 for sent_time in server_sent_times if sent_time > current_time - datetime.timedelta(seconds=1))
            client_received_count = sum(1 for received_time in client_received_times if
                                        received_time > current_time - datetime.timedelta(seconds=1))
            server_received_count = sum(1 for received_time in server_received_times if
                                        received_time > current_time - datetime.timedelta(seconds=1))

            client_sent_packets.append(client_sent_count)
            server_sent_packets.append(server_sent_count)
            client_received_packets.append(client_received_count)
            server_received_packets.append(server_received_count)

            plt.figure(1)
            plt.clf()
            plt.plot(range(1, seconds_counter + 1), client_sent_packets, label='Client Sent Packets', color='blue')
            plt.plot(range(1, seconds_counter + 1), server_sent_packets, label='Server Sent Packets', color='green')
            plt.xlabel('Time (seconds)')
            plt.ylabel('Packets')
            plt.legend(loc='upper center', bbox_to_anchor=(0.5, 1.09), ncol=2)
            plt.title('Sent Packets for Client and Server', y=1.08)

            plt.figure(2)
            plt.clf()
            plt.plot(range(1, seconds_counter + 1), client_received_packets, label='Client Received Packets',
                     linestyle='dashed', color='orange')
            plt.plot(range(1, seconds_counter + 1), server_received_packets, label='Server Received Packets',
                     linestyle='dashed', color='red')
            plt.xlabel('Time (seconds)')
            plt.ylabel('Packets')
            plt.legend(loc='upper center', bbox_to_anchor=(0.5, 1.09), ncol=2)
            plt.title('Received Packets for Client and Server', y=1.08)

            seconds_counter += 1
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
    print(f"Proxy sent to server: {client_data}")
    client_sent_times.append(datetime.datetime.now())


def handle_server_to_client(proxy_socket, client_addr, server_data):
    if should_drop_packet(DROP_SERVER_PACKET_PROBABILITY):
        print("Dropped packet from server")
        return

    if should_delay_packet(DELAY_SERVER_PACKET_PROBABILITY):
        delay_packet("server")

    proxy_socket.sendto(server_data, client_addr)
    print(f"Proxy sent to client: {server_data}")
    server_sent_times.append(datetime.datetime.now())


def send_packet(socket, packet, address):
    socket.sendto(packet.encode(), address)


def is_handshake_packet(data):
    if DROP_CLIENT_PACKET_PROBABILITY == 1 or DROP_SERVER_PACKET_PROBABILITY == 1:
        return False
    return (data.startswith(b"SYN") or data.startswith(b"SHAKE_ACK") or data.startswith(b"SYN-ACK") or data.startswith(
        b"FIN") or data.startswith(b"FIN-ACK") or data.startswith(b"PSH") or data.startswith(b"PSH-ACK") or
            data.startswith(b"COUNT_ACK") or data.startswith(b"RESULT"))


def handle_handshake_packet(packet, socket, address):
    socket.sendto(packet, address)
    print(f"Forwarded handshake packet to {address}: {packet}")


def main():
    global server_socket

    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    proxy_socket.bind((PROXY_IP, PROXY_PORT))

    print("Proxy is listening...")

    # Create server sckt
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
                    client_received_times.append(datetime.datetime.now())

                elif ready_socket == server_socket:
                    # Packet received from server
                    server_data, server_addr = server_socket.recvfrom(1024)
                    print(f"Received data from server: {server_data}")

                    # Forward packet to client
                    if is_handshake_packet(server_data):
                        handle_handshake_packet(server_data, proxy_socket, client_addr)
                    else:
                        handle_server_to_client(proxy_socket, client_addr, server_data)
                    server_received_times.append(datetime.datetime.now())

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

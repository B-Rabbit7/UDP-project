import socket
import sys
import os
import time

# Constants
SYN = "SYN"
ACK = "ACK"
SYN_ACK = "SYN-ACK"
FIN = "FIN"
PSH = "PSH"
FIN_ACK = "FIN-ACK"
SHAKE_ACK = "SHAKE_ACK"
PSH_ACK = "PSH_ACK"
COUNT_ACK = "COUNT_ACK"
ACK_REQUESTED = "ACK_REQUESTED"

PROXY_IP = "127.0.0.1"
PROXY_PORT = 8888
TIME_OUT = 5

global packet_number, packet_with_number


def handle_file(filename):
    """Open and validate the specified file."""
    try:
        file = open(filename, 'r')
        if not filename.endswith('.txt'):
            print(f"Error: File '{filename}' is not a text file")
            return None
        return file
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None
    except IsADirectoryError:
        print(f"Error: '{filename}' is a directory, not a text file.")
        return None
    except PermissionError:
        print(f"Error: Permission denied to read '{filename}'.")
        return None
    except Exception as error:
        print(f"Error: {error}")
        return None


def get_packet_count(filename, buffer_size):
    """Calculate the number of packets needed to transmit the file's data."""
    byte_size = os.stat(filename).st_size
    packet_count = byte_size // buffer_size
    if byte_size % buffer_size:
        packet_count += 1
    return packet_count


def send_syn(server_socket, udp_ip, udp_port):
    """Send SYN signal to server."""
    server_socket.sendto(SYN.encode(), (udp_ip, udp_port))
    print("Sent SYN")


def receive_syn_ack(server_socket):
    """Receive SYN-ACK signal from server."""
    syn_ack, addr = server_socket.recvfrom(1024)
    if syn_ack.decode() == SYN_ACK:
        print("Received SYN-ACK from server")
        return True
    else:
        print("Failed: Received invalid SYN-ACK from server")
        return False


def send_psh(server_socket, udp_ip, udp_port):
    """Send PSH signal to server."""
    server_socket.sendto(PSH.encode(), (udp_ip, udp_port))
    print("Sent PSH")


def send_final_ack(server_socket, udp_ip, udp_port):
    """Send final ACK signal to server."""
    server_socket.sendto(FIN_ACK.encode(), (udp_ip, udp_port))
    print("Sent final ACK")


def send_fin(server_socket, udp_ip, udp_port):
    """Send FIN signal to server."""
    server_socket.sendto(FIN.encode(), (udp_ip, udp_port))
    print("Sent FIN")


def receive_fin_ack(server_socket):
    """Receive FIN-ACK signal from server."""
    fin_ack, addr = server_socket.recvfrom(1024)
    if fin_ack.decode() == SHAKE_ACK:
        return True
    else:
        return False


def receive_fin(server_socket):
    """Receive FIN signal from server."""
    fin, addr = server_socket.recvfrom(1024)
    if fin.decode() == FIN:
        return True
    else:
        return False


def send_file_data(client_socket, udp_ip, udp_port, file_descriptor, packet_count, buffer_size):
    """Send file data over the UDP connection."""
    global packet_number, packet_with_number
    base = 0
    packets_sent = {}

    # Loop until all packets are sent and acknowledged
    while base < packet_count:
        # Send the next packet if it's within the range of packet count
        packet_number = base + 1
        packet_data = file_descriptor.read(buffer_size)
        packet_with_number = f"{packet_number}:{packet_data}"
        client_socket.sendto(packet_with_number.encode(), (udp_ip, udp_port))
        print(f"Sent packet {packet_number}")
        packets_sent[packet_number] = packet_data

        while True:
            # Check for acknowledgment
            try:
                client_socket.settimeout(TIME_OUT)
                ack, _ = client_socket.recvfrom(1024)
                ack_signal = ack.decode()
                print(f"Received ACK: {ack_signal}")

                # If server sends ACK
                if ack_signal == ACK:
                    print(f"Received ACK for {packet_number}")
                    break

                elif ack_signal.startswith("RESULT"):
                    return

                # If server sends int
                elif int(ack_signal) in packets_sent.keys():
                    print(f"Server requested packet number: {int(ack_signal)}")
                    packet_with_number = f"{int(ack_signal)}:{packets_sent[int(ack_signal)]}"
                    client_socket.sendto(packet_with_number.encode(), (udp_ip, udp_port))
                    print(f"Resent packet {int(ack_signal)}")



            except socket.timeout:
                client_socket.sendto(packet_with_number.encode(), (udp_ip, udp_port))
                print(f"Retransmitted packet {packet_number}")

        base += 1
    print(f"All packets sent")


def three_way_handshake(client_socket, udp_ip, udp_port):
    """Perform the 3-way handshake."""
    send_syn(client_socket, udp_ip, udp_port)
    if receive_syn_ack(client_socket):
        client_socket.sendto(SHAKE_ACK.encode(), (udp_ip, udp_port))
        print("Sent ACK to server")
        return True
    else:
        print("Handshake failed. Closing connection.")
        client_socket.close()
        return False


def four_way_handshake(client_socket, udp_ip, udp_port):
    """Perform the 4-way handshake."""
    send_fin(client_socket, udp_ip, udp_port)
    if receive_fin_ack(client_socket):
        print("Received ACK for FIN from server")
        time.sleep(0.0001)
        if receive_fin(client_socket):
            print("Received FIN from server")
            time.sleep(0.0001)
            send_final_ack(client_socket, udp_ip, udp_port)
            print("Sent final ACK to server")
            time.sleep(0.0001)
            return True
        else:
            print("Failed to receive FIN from server. Closing connection.")
            client_socket.close()
            return False
    else:
        print("Failed to receive ACK for FIN from server. Closing connection.")
        client_socket.close()
        return False


def authenticate(client_socket):
    """Authenticate the client."""
    authenticated = client_socket.recvfrom(1024)
    if authenticated[0] == PSH_ACK.encode():
        print("Client authenticated")
        return True
    else:
        print("Client authentication failed")
        return False


def main():
    if len(sys.argv) != 4:
        print("Error: Please provide exactly 3 arguments (the path to the text file).")
        sys.exit(1)

    udp_ip = sys.argv[1]
    udp_port = int(sys.argv[2])  # PROXY_PORT
    filename = sys.argv[3]

    ip_version = socket.AF_INET if ':' not in udp_ip else socket.AF_INET6
    client_socket = socket.socket(ip_version, socket.SOCK_DGRAM)

    # Initiating file descriptor
    file_descriptor = handle_file(filename)
    if file_descriptor is None:
        sys.exit(1)

    # Initiating packet count
    buffer_size = 512
    packet_count = get_packet_count(filename, buffer_size)
    if packet_count == 0:
        print("Empty file")
        sys.exit(1)

    # Client loop
    try:
        if client_socket is not None:
            if three_way_handshake(client_socket, udp_ip, udp_port):
                # Send PSH request
                send_psh(client_socket, udp_ip, udp_port)

                # Get authenticated
                if authenticate(client_socket):
                    # Send packet size
                    print("Sending packet size")
                    client_socket.sendto(str(packet_count).encode(), (udp_ip, udp_port))
                    print("Sending %s with %d packets" % (filename, packet_count))

                    # Loop until ACK for packet count is received
                    while True:
                        try:
                            client_socket.settimeout(TIME_OUT)
                            ack, _ = client_socket.recvfrom(1024)
                            ack_signal = ack.decode()
                            if ack_signal == COUNT_ACK:
                                print("Received ACK for packet count")
                                break
                            else:
                                print(f"Received unexpected signal: {ack_signal}")
                        except socket.timeout:
                            print("Timeout: Resending packet count")
                            client_socket.sendto(str(packet_count).encode(), (udp_ip, udp_port))

                    # Sending file data
                    send_file_data(client_socket, udp_ip, udp_port, file_descriptor, packet_count, buffer_size)
                    results, addr = client_socket.recvfrom(1024)

                    print(results.decode())

                    # Start 4-way handshake
                    if four_way_handshake(client_socket, udp_ip, udp_port):
                        file_descriptor.close()
                        client_socket.close()
                else:
                    print("Client could not be authenticated")
                    client_socket.close()
    except socket.error as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    main()

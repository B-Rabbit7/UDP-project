import socket
import signal
import sys
import time

SYN = "SYN"
ACK = "ACK"
SYN_ACK = "SYN-ACK"
FIN = "FIN"
FIN_ACK = "FIN-ACK"
NACK = "NACK"
SHAKE_ACK = "SHAKE_ACK"

PROXY_IP = "127.0.0.1"
PROXY_PORT = 8889

running = True
clients = set()  # Set of verified clients


def get_character_count(text):
    """
    Calculate the number of characters in the given text.

    Parameters:
    - text (str): The input text.

    Returns:
    - int: The number of characters in the text.
    """
    return len(text)


def get_word_count(text):
    """
    Calculate the number of words in the given text.

    Parameters:
    - text (str): The input text.

    Returns:
    - int: The number of words in the text.
    """
    num_word = 0
    for _ in text.split():
        num_word += 1
    return num_word


def get_frequency_of_chars(text):
    """
    Calculate the frequency of each character in the given text.

    Parameters:
    - text (str): The input text.

    Returns:
    - dict: A dictionary containing the frequency of each character.
    """
    char_dict = {chr(char): 0 for char in text.lower()}
    for letter in text.lower():
        char_dict[chr(letter)] += 1
    return char_dict


def signal_handler(sig, frame):
    """
    Handle the SIGINT signal (Ctrl+C) to gracefully shut down the server.

    Parameters:
    - sig: The signal number.
    - frame: The current stack frame.
    """
    global running
    print(f"Shutting down server... received signal {sig} and frame {frame}")
    running = False
    sys.exit(0)


def send_packet(socket, packet, address):
    """Send a packet to the specified address."""
    socket.sendto(packet.encode(), address)


def receive_packet(socket):
    """Receive a packet from the socket."""
    return socket.recvfrom(1024)


def send_syn_ack(client_socket, address):
    """Send a SYN-ACK response to the client."""
    send_packet(client_socket, SYN_ACK, address)
    print("Sent SYN-ACK to Client")


def receive_syn(client_socket):
    """Receive a SYN request from the client."""
    syn, addr = receive_packet(client_socket)
    if syn.decode() == SYN:
        print("Received SYN from Client")
        return True, addr
    else:
        print("Failed: Received SYN response from Client")
        return False, None


def receive_final_ack(client_socket):
    """Receive a final ACK response from the client."""
    try:
        final_ack, addr = receive_packet(client_socket)
        if final_ack.decode() == FIN_ACK:
            print("Received final ACK from Client")
            return True
        else:
            print("Failed: Received invalid response from Client")
            return False
    except Exception as e:
        print(f"Failed: Error receiving final ACK - {e}")
        return False


def authenticate_client(client_socket, address):
    """Authenticate the client."""
    print("Authenticating client...")
    time.sleep(0.5)
    if address in clients:
        print("Client authenticated")
        send_packet(client_socket, ACK, address)
        print('Sent ACK for PSH to client')
        return True
    else:
        print("Client not authenticated")
        send_packet(client_socket, NACK, address)
        print('Sent NACK for PSH to client')
        return False


def process_data(packets):
    """
    Process the received data packets.

    Parameters:
    - packets (list): A list of data packets received.

    Returns:
    - str: A response containing the analysis results of the received data.
    """
    packet_dict = {}
    for packet in packets:
        packet_number, packet_data = packet.split(b':', 1)
        packet_dict[int(packet_number)] = packet_data

    expected_packet_number = 1
    for i in range(expected_packet_number, len(packet_dict) + 1):
        if i not in packet_dict:
            print(f"Missing packet: {i}")
            return "Missing packet"
        elif i == len(packet_dict):
            break
        expected_packet_number += 1

    received_data = b''.join(packet_dict[i] for i in range(1, len(packet_dict) + 1))

    try:
        character_count = get_character_count(received_data)
        word_count = get_word_count(received_data)
        frequency = get_frequency_of_chars(received_data)
        response = (f'Server Response:\n\tCharacter count: {character_count}\n\tWords: {word_count}\n\t'
                    f'Frequency:{frequency}')
        print("Processed data successfully")
        return response
    except UnicodeDecodeError:
        print("Data is not valid UTF-8, handle as binary or other encoding")


def handle_client_request(client_socket, address):
    """Handle a client request."""
    while True:
        try:
            print('Waiting for client request')
            first_request, _ = receive_packet(client_socket)
            first_packet = first_request.decode()

            if first_packet == 'FIN':
                print('Received FIN from client')
                send_packet(client_socket, SHAKE_ACK, address)
                print('Sent ACK for FIN to client')
                send_packet(client_socket, FIN, address)
                print('Sent own FIN to client')
                if receive_final_ack(client_socket):
                    print('Received final ACK from client')
                    break
                else:
                    print('Failed: Did not receive final ACK from client after sending FIN')
            elif first_packet == 'PSH':
                print("Received PSH from client")
                if authenticate_client(client_socket, address):
                    packet_count, _ = receive_packet(client_socket)
                    packet_count = int(packet_count.decode())
                    print('Received packet count:', packet_count)
                    packets = []

                    # receiving data from the client
                    for i in range(packet_count):
                        packet, _ = receive_packet(client_socket)
                        print(f"packet on server: {packet}")
                        packet_number, packet_data = packet.split(b':', 1)
                        packet_number = int(packet_number.decode())

                        # If the received packet is out of order
                        while not packet_number == i + 1:
                            print(f"Received packet number:{packet_number} expecting {i + 1}")
                            print(f"Sending NACK for packet with needed packet number of {i + 1}")
                            send_packet(client_socket, str(i + 1), address)
                            retransmitted_packet,_ = receive_packet(client_socket)
                            packet_number, packet_data = retransmitted_packet.split(b':', 1)
                            packet_number = int(packet_number.decode())
                            print(f"Received packet number after NACK {packet_number}")

                        # If received packet is in order
                        packets.append(packet)
                        send_packet(client_socket, ACK, address)  # Send ACK for each packet received

                    results = process_data(packets)
                    print(results)
                    send_packet(client_socket, results, address)
                else:
                    break
            else:
                print("Client has not made specific requests")
        except socket.error as e:
            print(e)
            break


def perform_three_way_handshake(server_socket):
    """
    Perform the 3-way handshake with the client.

    Parameters:
    - server_socket (socket): The server socket.

    Returns:
    - bool: True if the handshake is successful, False otherwise.
    - tuple: The client address if the handshake is successful, None otherwise.
    """
    try:
        # Receive SYN
        syn, client_addr = server_socket.recvfrom(1024)
        if syn.decode() == SYN:
            print("Received SYN from Client")
        else:
            print("Failed: Received SYN response from Client")
            return False, None

        # Send SYN-ACK
        server_socket.sendto(SYN_ACK.encode(), client_addr)
        print("Sent SYN-ACK to Client")

        # Receive final ACK
        final_ack, _ = server_socket.recvfrom(1024)
        if final_ack.decode() == SHAKE_ACK:
            print("Received final ACK from Client")
            return True, client_addr
        else:
            print("Failed: Received invalid response from Client")
            return False, None
    except Exception as e:
        print(f"Failed: Error during 3-way handshake - {e}")
        return False, None


def main():
    """
    Main function to start the server.

    This function initializes the server, binds it to the specified IP address and port,
    and listens for incoming data packets. It processes the received data and sends
    the analysis results back to the client.
    """
    global running
    running = True

    # set up socket and SIGINT
    ip_version = socket.AF_INET if ':' not in PROXY_IP else socket.AF_INET6
    server_socket = socket.socket(ip_version, socket.SOCK_DGRAM)
    server_socket.bind((PROXY_IP, PROXY_PORT))
    signal.signal(signal.SIGINT, signal_handler)

    # Server loop
    while running:
        try:
            print("Server is listening for incoming connections...")

            handshake_success, client_addr = perform_three_way_handshake(server_socket)
            if handshake_success:
                print(f"Connection established with client {client_addr}")
                clients.add(client_addr)
                print(f'Client {client_addr} added to verified client list')
                handle_client_request(server_socket, client_addr)
                print("Connection with client ended.")

        except socket.error as e:
            print(e)
            running = False


if __name__ == '__main__':
    main()

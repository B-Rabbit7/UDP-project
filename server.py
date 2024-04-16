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
TIME_OUT = 4
global packet_number, packet_count


def get_character_count(text):
    return len(text)


def get_word_count(text):
    num_word = 0
    for _ in text.split():
        num_word += 1
    return num_word


def get_frequency_of_chars(text):
    char_dict = {char: 0 for char in text.lower()}
    for letter in text.lower():
        char_dict[letter] += 1
    return char_dict


def signal_handler(sig, frame):
    global running
    print(f"Shutting down server... received signal {sig} and frame {frame}")
    running = False
    sys.exit(0)


def send_packet(sckt, packet, address):
    sckt.sendto(packet.encode(), address)


def receive_packet(sckt):
    return sckt.recvfrom(1024)


def send_syn_ack(client_socket, address):
    send_packet(client_socket, SYN_ACK, address)
    print("Sent SYN-ACK to Client")


def receive_syn(client_socket):
    syn, addr = receive_packet(client_socket)
    if syn.decode() == SYN:
        print("Received SYN from Client")
        return True, addr
    else:
        print("Failed: Received SYN response from Client")
        return False, None


def receive_final_ack(client_socket):
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
    expected_packet_number = 1
    for i in range(expected_packet_number, len(packets) + 1):
        if i not in packets:
            print(f"Missing packet: {i}")
            return "Missing packet"
        elif i == len(packets):
            break
        expected_packet_number += 1

    received_data = ''.join(packets[i] for i in range(1, len(packets) + 1))

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


def print_items(packet_list):
    for item in packet_list:
        print(item)


def find_duplicates_and_unique(lst):
    seen = set()
    duplicates = set()
    unique_items = []
    for item in lst:
        key, _ = item.split(b':', 1)
        if key in seen:
            duplicates.add(key)
        else:
            unique_items.append(item)
            seen.add(key)

    if duplicates:
        print("Duplicates:", end=" ")  # Print without newline
        print(", ".join(d.decode() for d in duplicates))  # Print duplicates separated by comma
        print("Dropping duplicates...")
        time.sleep(0.005)
    else:
        print("No duplicates")

    unique_items_length = len(unique_items)
    print("Length of unique items:", unique_items_length)

    return unique_items


def list_to_dict(lst):
    result_dict = {}
    for item in lst:
        key, value = item.split(b':', 1)
        result_dict[int(key.decode())] = value.decode()
    return result_dict


def print_dict(dictionary):
    for key, value in dictionary.items():
        print(f"Key: {key}")


def reorder_dict(dictionary):
    print("Reordering Packets")
    sorted_dict = dict(sorted(dictionary.items(), key=lambda item: item[0]))
    return sorted_dict


def handle_client_request(client_socket, address):
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
                    packet_with_sequence = []

                    # Send acknowledgment for the packet count
                    send_packet(client_socket, ACK, address)
                    print('Sent ACK for packet count')

                    # receiving data from the client
                    for i in range(packet_count):
                        while True:
                            try:
                                client_socket.settimeout(TIME_OUT)
                                packet, _ = receive_packet(client_socket)
                                packet_number, packet_data = packet.split(b':', 1)
                                packet_number = int(packet_number.decode())
                                print(f"Received packet number: {packet_number}")
                                packet_with_sequence.append(packet)
                                
                                # If the received packet is out of order
                                while not packet_number == i + 1:
                                    print(f"Received packet number:{packet_number} expecting {i + 1}")
                                    print(f"Sending NACK for packet with needed packet number of {i + 1}")
                                    send_packet(client_socket, str(i + 1), address)
                                    retransmitted_packet, _ = receive_packet(client_socket)
                                    packet_number, packet_data = retransmitted_packet.split(b':', 1)
                                    packet_number = int(packet_number.decode())
                                    packet_with_sequence.append(retransmitted_packet)
                                    print(f"Received packet number after NACK {packet_number}")

                                # If received packet is in order
                                packets.append(packet)
                                send_packet(client_socket, ACK, address)  # Send ACK for each packet received
                                break
                            # Timeout and no packet sent that met criteria
                            except socket.timeout:
                                print(f"Retransmitting packet {packet_number}")

                    unique_packets = find_duplicates_and_unique(packet_with_sequence)
                    result_dict = list_to_dict(unique_packets)
                    new_dict = reorder_dict(result_dict)
                    results = process_data(new_dict)
                    send_packet(client_socket, results, address)


                ## else of the if
                else:
                    break
            else:
                print("Client has not made specific requests")
        except socket.error as e:
            print(e)
            break


def perform_three_way_handshake(server_socket):
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
    global running
    running = True

    # set up sckt and SIGINT
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
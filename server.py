"""
Created on Sat Feb 24
@author: Set & Jason
Student Number: A01308077 & A10307299

The purpose of this server is to provide character count, word count, and character frequency analysis for the text
data it receives over UDP (User Datagram Protocol). It listens for incoming data packets, aggregates them,
and performs the requested analysis once all packets are received. It gracefully handles the termination signal (
Ctrl+C) for a clean shutdown.
"""
import socket
import signal
import sys
import time

running = True
packet_size = False
global server_socket
UDP_IP = "127.0.0.1"
UDP_PORT = 5005
SYN = "SYN"
ACK = "ACK"
SYN_ACK = "SYN-ACK"
FIN = "FIN"
FIN_ACK = "FIN-ACK"


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


def process_data(packets):
    """
    Process the received data packets.

    Parameters:
    - packets (list): A list of data packets received.

    Returns:
    - str: A response containing the analysis results of the received data.
    """
    received_data = b''.join(packets)
    try:
        character_count = get_character_count(received_data)
        word_count = get_word_count(received_data)
        frequency = get_frequency_of_chars(received_data)
        response = (f'Server Response:\n\tCharacter count: {character_count}\n\tWords: {word_count}\n\t'
                    f'Frequency:{frequency}')
        return response
    except UnicodeDecodeError:
        print("Data is not valid UTF-8, handle as binary or other encoding")

def send_syn_ack(client_socket, address):
    """
    Send a SYN-ACK response to the client.

    Parameters:
    - client_socket (socket): The client socket.
    - address (str): The client address.
    """
    client_socket.sendto(SYN_ACK.encode(), address)
    print("Sent SYN-ACK to Client")

def receive_syn(client_socket):
    """
    Receive a SYN request from the client.

    Parameters:
    - client_socket (socket): The client socket.
    """
    syn, addr = client_socket.recvfrom(1024)
    if syn.decode() == SYN:
        print("Received SYN from Client")
        return True, addr
    else:
        print("Failed: Received SYN response from Client")
        return False, None
    
def receive_final_ack(client_socket):
    """
    Receive a final ACK response from the client.

    Parameters:
    - client_socket (socket): The client socket.
    """
    try:
        final_ack, addr = client_socket.recvfrom(1024)
        if final_ack.decode() == ACK:
            print("Received final ACK from Client")
            return True
        else:
            print("Failed: Received invalid response from Client")
            return False
    except Exception as e:
        print(f"Failed: Error receiving final ACK - {e}")
        return False

def main():
    """
    Main function to start the server.

    This function initializes the server, binds it to the specified IP address and port,
    and listens for incoming data packets. It processes the received data and sends
    the analysis results back to the client.
    """
    global running
    running = True

    ip_version = socket.AF_INET if ':' not in UDP_IP else socket.AF_INET6
    server_socket = socket.socket(ip_version, socket.SOCK_DGRAM)
    server_socket.bind((UDP_IP, UDP_PORT))
    signal.signal(signal.SIGINT, signal_handler)

    while running:
        try:
            print("Server is listening for incoming connections...")
            syn_received, client_addr = receive_syn(server_socket)
            if syn_received:
                send_syn_ack(server_socket, client_addr)
                if receive_final_ack(server_socket):
                    print(f"Connection established with client {client_addr}")

                    packets = []
                    expected_packet_count = True

                    while expected_packet_count:
                        try:
                            if packets:
                                print('Received all packets, processing content analysis')
                                results = process_data(packets)
                                print(results)
                                server_socket.sendto(results.encode(), client_addr)
                                packets = []
                            else:
                                print('Waiting for packet count or FIN from client')
                                packet_count_data, _ = server_socket.recvfrom(1024)
                                packet_count = packet_count_data.decode()
                                # 4-way handshake
                                if packet_count == 'FIN':
                                    print('Received FIN from client')
                                    server_socket.sendto(ACK.encode(), client_addr)
                                    print('Sent ACK for FIN to client')
                                    server_socket.sendto(FIN.encode(), client_addr)
                                    print(FIN.encode())
                                    print(client_addr)
                                    print('Sent own FIN to client')
                                    final_ack_data, _ = server_socket.recvfrom(1024)
                                    if final_ack_data.decode() == ACK:
                                        print('Received final ACK from client')
                                        expected_packet_count = False
                                    else:
                                        print('Failed: Did not receive final ACK from client after sending FIN')
                                else:
                                    packet_count = int(packet_count)
                                    print('Received packet count:', packet_count)
                                    for _ in range(packet_count):
                                        data, _ = server_socket.recvfrom(1024)
                                        packets.append(data)
                        except socket.error as e:
                            print(e)
                            running = False
                    print("Connection with client ended.")
                else:
                    print("Failed: Did not receive final ACK from client")
            else:
                print("Failed: Did not receive SYN from client")
        except socket.error as e:
            print(e)
            running = False


if __name__ == '__main__':
    main()

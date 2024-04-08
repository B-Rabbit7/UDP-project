"""
Created on Sat Feb 24
@author: Set & Jason
Student Number: A01308077 & A10307299

The purpose of this client script is to read a text file specified by the user and send its contents over a UDP
connection to a server for analysis. It calculates the number of packets needed to transmit the file's data based on
a predefined buffer size. The client then sends each packet sequentially, along with a special "END" packet to signal
the completion of file transmission, and waits for the server's response containing the analysis results.
"""
import socket
import sys
import os
import time

SYN = "SYN"
ACK = "ACK"
SYN_ACK = "SYN-ACK"
FIN = "FIN"

time_out = 4

def handle_file(filename):
    """
    Open and validate the specified file.

    Parameters:
    - filename (str): The path to the file to be opened.

    Returns:
    - file object or None: The file object if the file is successfully opened, otherwise None.
    """
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
    """
    Calculate the number of packets needed to transmit the file's data.

    Parameters:
    - filename (str): The path to the file.
    - buffer_size (int): The size of each packet.

    Returns:
    - int: The number of packets needed.
    """
    byte_size = os.stat(filename).st_size

    packet_count = byte_size // buffer_size

    if byte_size % buffer_size:
        packet_count += 1

    return packet_count


def send_syn(server_socket, udp_ip, udp_port):
    server_socket.sendto(SYN.encode(), (udp_ip, udp_port))
    print("Sent SYN")


def receive_syn_ack(server_socket):
    syn_ack, addr = server_socket.recvfrom(1024)
    if syn_ack.decode() == SYN_ACK:
        print("Received SYN-ACK from server")
        return True
    else:
        print("Failed: Received invalid SYN-ACK from server")
        return False


def send_final_ack(server_socket, udp_ip, udp_port):
    server_socket.sendto(ACK.encode(), (udp_ip, udp_port))
    print("Sent final ACK")


def send_fin(server_socket, udp_ip, udp_port):
    server_socket.sendto(FIN.encode(), (udp_ip, udp_port))
    print("Sent FIN")


def receive_fin_ack(server_socket):
    fin_ack, addr = server_socket.recvfrom(1024)
    print(fin_ack.decode())
    if fin_ack.decode() == ACK:
        print("Received ACK for FIN from server")
        return True
    else:
        print("Failed: Received invalid ACK for FIN from server")
        return False


def receive_fin(server_socket):
    fin, addr = server_socket.recvfrom(1024)
    if fin.decode() == FIN:
        print("Received FIN from server")
        return True
    else:
        print("Failed: Received invalid FIN from server")
        return False


def send_final_ack(server_socket, udp_ip, udp_port):
    server_socket.sendto(ACK.encode(), (udp_ip, udp_port))
    print("Sent final ACK")


def main():
    buffer_size = 512
    if len(sys.argv) != 4:
        print("Error: Please provide exactly 3 arguments (the path to the text file).")
        sys.exit(1)

    udp_ip = sys.argv[1]
    udp_port = int(sys.argv[2])
    filename = sys.argv[3]

    ip_version = socket.AF_INET if ':' not in udp_ip else socket.AF_INET6
    client_socket = socket.socket(ip_version, socket.SOCK_DGRAM)

    # set default time-out
    client_socket.settimeout(time_out)
    print(f'Client default timeout: {time_out}s')

    file_descriptor = handle_file(filename)

    if file_descriptor is None:
        sys.exit(1)
    packet_count = get_packet_count(filename, buffer_size)
    if packet_count == 0:
        print("Empty file")
        sys.exit(1)

    try:
        if client_socket is not None:
            send_syn(client_socket, udp_ip, udp_port)
            if receive_syn_ack(client_socket):
                # Send ACK to complete the three-way handshake
                client_socket.sendto(ACK.encode(), (udp_ip, udp_port))
                print("Sent ACK to server")
                print("Sending packet size")
                client_socket.sendto(str(packet_count).encode(), (udp_ip, udp_port))
                print("Sending %s with %d packets" % (filename, packet_count))
                time.sleep(0.0001)
                for i in range(0, packet_count):
                    client_socket.sendto(file_descriptor.read(buffer_size).encode(), (udp_ip, udp_port))
                    time.sleep(0.0001)

                # Print results
                results, addr = client_socket.recvfrom(1024)
                print(results.decode())

                # 4-way handshake
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
                        file_descriptor.close()
                        client_socket.close()
                    else:
                        print("Failed to receive FIN from server. Closing connection.")
                        client_socket.close()
                else:
                    print("Failed to receive ACK for FIN from server. Closing connection.")
                    client_socket.close()
            else:
                print("Handshake failed. Closing connection.")
                client_socket.close()
    except socket.error as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    main()

import select
import socket

# Proxy configuration
PROXY_IP = "127.0.0.1"
PROXY_PORT = 8888

# Server configuration
SERVER_IP = "127.0.0.1"
SERVER_PORT = 8889


def handle_client_to_server(client_data, server_socket):
    server_socket.sendto(client_data, (SERVER_IP, SERVER_PORT))


def handle_server_to_client(proxy_socket, client_addr):
    server_data, _ = proxy_socket.recvfrom(1024)
    proxy_socket.sendto(server_data, client_addr)


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
                    handle_client_to_server(client_data, server_socket)

                elif ready_socket == server_socket:
                    # Packet received from server
                    server_data, server_addr = server_socket.recvfrom(1024)
                    print(f"Received data from server: {server_data}")

                    # Forward packet to client
                    proxy_socket.sendto(server_data, client_addr)
                    print(f"Proxy sent to client: {server_data}")

    except KeyboardInterrupt:
        print("Proxy shutting down...")
    finally:
        proxy_socket.close()
        server_socket.close()


if __name__ == "__main__":
    main()

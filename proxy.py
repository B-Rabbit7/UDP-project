import socket
import threading

# Proxy configuration
PROXY_IP = "127.0.0.1"
PROXY_PORT = 8888

# Server configuration
SERVER_IP = "127.0.0.1"
SERVER_PORT = 8889

# Client configuration
CLIENT_IP = "127.0.0.1"
CLIENT_PORT = 8080


def handle_client_to_server(client_data, server_socket):
    server_socket.sendto(client_data, (SERVER_IP, SERVER_PORT))


def handle_server_to_client(client_socket, server_data):
    client_socket.sendto(server_data, (CLIENT_IP, CLIENT_PORT))


# Handle client function definition
def handle_client(client_socket, client_data):
    print(client_data)
    try:
        # Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        while True:
            # Receive data from client
            client_data, _ = client_socket.recvfrom(1024)
            if not client_data:
                break
            print("Received message: {}".format(client_data))

            # Forward data to server
            handle_client_to_server(client_data, server_socket)

            # Receive response from server
            server_data, _ = server_socket.recvfrom(1024)

            # Forward response to client
            handle_server_to_client(client_socket, server_data)

    except Exception as e:
        print(f"Error: {e}")


# Main function
def main():
    # Create proxy socket
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    proxy_socket.bind((PROXY_IP, PROXY_PORT))

    print("Proxy is listening...")

    try:
        while True:
            # Accept client connection
            client_data, client_addr = proxy_socket.recvfrom(1024)
            proxy_socket.sendto(client_data, (SERVER_IP, SERVER_PORT))
            print(f"Accepted connection from client: {client_addr}")
            print(f"Received data from client: {client_data}")

            # Handle client in a separate thread
            # client_thread = threading.Thread(target=handle_client, args=(proxy_socket, client_data))
            # client_thread.start()

    except KeyboardInterrupt:
        print("Proxy shutting down...")
    finally:
        proxy_socket.close()


if __name__ == "__main__":
    main()

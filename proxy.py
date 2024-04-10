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
            # Receive request from client
            client_data, client_addr = proxy_socket.recvfrom(1024)
            print(f"Received data from client: {client_data}")

            # Forward request to server
            handle_client_to_server(client_data, server_socket)

            # Receive response from server
            server_data, _ = server_socket.recvfrom(1024)
            print(f"Received data from server: {server_data}")

            # Forward response to client
            proxy_socket.sendto(server_data, client_addr)

    except KeyboardInterrupt:
        print("Proxy shutting down...")
    finally:
        proxy_socket.close()
        server_socket.close()
        
if __name__ == "__main__":
    main()

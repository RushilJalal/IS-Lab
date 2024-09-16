import socket
import hashlib


def compute_hash(data):
    # Compute SHA-256 hash of the data
    return hashlib.sha256(data).hexdigest()


def handle_client(client_socket):
    # Receive data from the client
    data = client_socket.recv(1024)
    if not data:
        return

    # Compute the hash of the received data
    data_hash = compute_hash(data)

    # Send back the hash to the client
    client_socket.sendall(data_hash.encode())

    # Close the connection
    client_socket.close()


def main():
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_socket.bind(("localhost", 12345))

    # Listen for incoming connections
    server_socket.listen(1)
    print("Server listening on port 12345...")

    while True:
        # Wait for a connection
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        handle_client(client_socket)


if __name__ == "__main__":
    main()

import socket
import hashlib

def compute_hash(data):
    # Compute SHA-256 hash of the data
    return hashlib.sha256(data).hexdigest()

def main():
    # Data to be sent to the server
    data = b"Hello, this is a test message."

    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect the socket to the server's address and port
    client_socket.connect(('localhost', 12345))
    
    # Send the data to the server
    client_socket.sendall(data)
    
    # Receive the hash from the server
    server_hash = client_socket.recv(64).decode()
    
    # Compute the hash of the sent data locally
    local_hash = compute_hash(data)
    
    # Print the results
    print(f"Local Hash: {local_hash}")
    print(f"Server Hash: {server_hash}")

    # Verify the hash
    if local_hash == server_hash:
        print("Data integrity verified. The data was not tampered with.")
    else:
        print("Data integrity check failed. The data may have been tampered with.")

    # Close the connection
    client_socket.close()

if __name__ == "__main__":
    main()

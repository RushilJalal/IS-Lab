import socket

# Create a UDP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the address and port
server_address = ("localhost", 65432)
server_socket.bind(server_address)

print("UDP server is up and listening...")

while True:
    # Receive data
    data, client_address = server_socket.recvfrom(1024)
    print(f"Received: {data.decode()} from {client_address}")

    # Send the same data back to the client (echo)
    server_socket.sendto(data, client_address)

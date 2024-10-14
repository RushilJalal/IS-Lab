import socket

# Create a UDP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_address = ("localhost", 65432)
message = "Hello, UDP server!"

try:
    # Send data
    print(f"Sending: {message}")
    client_socket.sendto(message.encode(), server_address)

    # Receive response
    data, server = client_socket.recvfrom(1024)
    print(f"Received: {data.decode()}")

finally:
    client_socket.close()

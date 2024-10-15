# client.py
import socket


def send_message(message):
    host = "127.0.0.1"
    port = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    client_socket.send(message.encode())
    response = client_socket.recv(1024).decode()
    print(f"Server response: {response}")
    client_socket.close()


if __name__ == "__main__":
    message = input("Enter message to send: ")
    send_message(message)

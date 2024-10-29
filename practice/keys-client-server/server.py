# server.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from datetime import datetime
import socket
import json
import base64
import pickle
import logging


class Server:
    def __init__(self, host="localhost", port=5000):
        self.host = host
        self.port = port
        self.audit_log = {}
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            filename="audit.log",
            level=logging.INFO,
            format="%(asctime)s:%(levelname)s:%(message)s",
        )

    def verify_signature(self, public_key, signature, data):
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        print(f"Server listening on {self.host}:{self.port}")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr}")

            # Receive data from client
            data = client_socket.recv(4096)
            received_data = pickle.loads(data)

            # Extract components
            encrypted_data = received_data["encrypted_data"]
            signature = received_data["signature"]
            public_key_pem = received_data["public_key"]
            doc_hash = received_data["hash"]
            timestamp = received_data["timestamp"]

            for key, value in received_data.items():
                if isinstance(value, bytes):
                    print(f"{key}: {base64.b64encode(value).decode()}")
                else:
                    print(f"{key}: {value}")

            # Load public key
            public_key = serialization.load_pem_public_key(public_key_pem)

            # Verify signature
            if self.verify_signature(public_key, signature, encrypted_data):
                print("Signature verified successfully")

                # Log the transaction
                log_entry = {
                    "timestamp": timestamp,
                    "encrypted_data": base64.b64encode(encrypted_data).decode(),
                    "hash": base64.b64encode(doc_hash).decode(),
                }

                print(log_entry["encrypted_data"])
                print(log_entry["hash"])
                self.audit_log[timestamp] = log_entry
                logging.info(f"New transaction logged: {timestamp}")

                client_socket.send(b"Signature verified and data logged")
            else:
                print("Signature verification failed")
                client_socket.send(b"Signature verification failed")

            client_socket.close()


if __name__ == "__main__":
    server = Server()
    server.start()

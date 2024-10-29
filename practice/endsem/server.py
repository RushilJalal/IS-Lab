# server.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from datetime import datetime
import socket
import json
import base64
import pickle
from cryptography.fernet import Fernet
import logging
from seal import EncryptionParameters, SEALContext, Encryptor, Evaluator


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

    def process_homomorphic_data(self, encrypted_data, operation, value):
        evaluator = Evaluator(SEALContext(EncryptionParameters()))
        if operation == "add":
            return evaluator.add(encrypted_data, value)
        elif operation == "multiply":
            return evaluator.multiply(encrypted_data, value)

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
            public_key = received_data["public_key"]
            doc_hash = received_data["hash"]
            is_homomorphic = received_data["is_homomorphic"]
            timestamp = received_data["timestamp"]

            # Verify signature
            if self.verify_signature(public_key, signature, encrypted_data):
                print("Signature verified successfully")

                # Log the transaction
                log_entry = {
                    "timestamp": timestamp,
                    "encrypted_data": base64.b64encode(encrypted_data).decode(),
                    "hash": doc_hash,
                    "is_homomorphic": is_homomorphic,
                }
                self.audit_log[timestamp] = log_entry
                logging.info(f"New transaction logged: {timestamp}")

                # Process based on encryption type
                if is_homomorphic:
                    print("\n1. Add")
                    print("2. Multiply")
                    choice = input("Select operation: ")
                    value = float(input("Enter value: "))

                    result = self.process_homomorphic_data(
                        encrypted_data, "add" if choice == "1" else "multiply", value
                    )
                    client_socket.send(pickle.dumps(result))
                else:
                    choice = input("Decrypt data? (y/n): ")
                    if choice.lower() == "y":
                        client_socket.send(b"DECRYPT")
                    else:
                        client_socket.send(b"KEEP_ENCRYPTED")

            else:
                print("Signature verification failed")
                client_socket.send(b"SIGNATURE_FAILED")

            client_socket.close()

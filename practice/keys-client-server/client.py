# client.py

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from datetime import datetime
import socket
import json
import base64
import pickle


class Client:
    def __init__(self, host="localhost", port=5000):
        self.host = host
        self.port = port
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()

    def encrypt_data(self, data):
        # Generate a symmetric key
        shared_key = self.private_key.exchange(ec.ECDH(), self.public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
            backend=default_backend(),
        ).derive(shared_key)

        # Encrypt the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        iv = b"\x00" * 16  # Initialization vector
        cipher = Cipher(
            algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return ciphertext

    def sign_data(self, data):
        signature = self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return signature

    def calculate_hash(self, data):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        return digest.finalize()

    def send_data(self, data):
        # Connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))

        # Encrypt data
        encrypted_data = self.encrypt_data(data)

        # Generate signature and hash
        signature = self.sign_data(encrypted_data)
        doc_hash = self.calculate_hash(encrypted_data)

        # Prepare data package
        data_package = {
            "encrypted_data": encrypted_data,
            "signature": signature,
            "public_key": self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            "hash": doc_hash,
            "timestamp": datetime.now().isoformat(),
        }

        for key, value in data_package.items():
            if isinstance(value, bytes):
                print(f"{key}: {base64.b64encode(value).decode()}")
            else:
                print(f"{key}: {value}")

        # Send to server
        client_socket.send(pickle.dumps(data_package))

        # Receive response
        response = client_socket.recv(4096)
        print("Server response:", response.decode())

        client_socket.close()


if __name__ == "__main__":
    client = Client()
    while True:
        data = input("Enter data to send (or 'quit' to exit): ")
        if data.lower() == "quit":
            break
        client.send_data(data)

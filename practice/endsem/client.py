# client.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta
import socket
import json
import base64
import pickle
import re
from seal import EncryptionParameters, SEALContext, Encryptor, KeyGenerator

class Client:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.private_key = None
        self.public_key = None
        self.key_generation_time = None
        self.setup_homomorphic_encryption()
        
    def setup_homomorphic_encryption(self):
        params = EncryptionParameters()
        context = SEALContext(params)
        keygen = KeyGenerator(context)
        self.homomorphic_public_key = keygen.public_key()
        self.homomorphic_secret_key = keygen.secret_key()
        self.encryptor = Encryptor(context, self.homomorphic_public_key)
        
    def generate_ecc_keys(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.private_key.public_key()
        self.key_generation_time = datetime.now()
        
    def check_key_expiration(self):
        if (self.key_generation_time is None or 
            datetime.now() - self.key_generation_time > timedelta(seconds=10)):
            self.generate_ecc_keys()
            
    def encrypt_data(self, data):
        if data.isdigit():
            # Homomorphic encryption for numbers
            encrypted = self.encryptor.encrypt(float(data))
            return encrypted, True
        else:
            # ECC encryption for text
            key = Fernet.generate_key()
            f = Fernet(key)
            encrypted = f.encrypt(data.encode())
            return encrypted, False
            
    def sign_data(self, data):
        self.check_key_expiration()
        signature = self.private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return signature
        
    def calculate_hash(self, data):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()
        
    def send_data(self, data):
        # Connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))
        
        # Encrypt data
        encrypted_data, is_homomorphic = self.encrypt_data(data)
        
        # Generate signature and hash
        signature = self.sign_data(encrypted_data)
        doc_hash = self.calculate_hash(encrypted_data)
        
        # Prepare data package
        data_package = {
            'encrypted_data': encrypted_data,
            'signature': signature,
            'public_key': self.public_key,
            'hash': doc_hash,
            'is_homomorphic': is_homomorphic,
            'timestamp': datetime.now().isoformat()
        }
        
        # Send to server
        client_socket.send(pickle.dumps(data_package))
        
        # Receive response
        response = client_socket.recv(4096)
        
        if response == b"DECRYPT":
            print("Decrypted data:", data)
        elif response == b"SIGNATURE_FAILED":
            print("Signature verification failed")
        elif response == b"KEEP_ENCRYPTED":
            print("Data kept encrypted")
        else:
            # Homomorphic operation result
            result = pickle.loads(response)
            print("Operation result:", result)
            
        client_socket.close()

# Usage example
if __name__ == "__main__":
    # Start server in a separate process/thread
    server = Server()
    import threading
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # Create client and send data
    client = Client()
    while True:
        data = input("Enter data to send (or 'quit' to exit): ")
        if data.lower() == 'quit':
            break
        client.send_data(data)
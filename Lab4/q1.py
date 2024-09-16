from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


# Key Management System
class KeyManagement:
    def __init__(self):
        self.private_keys = {}
        self.public_keys = {}

    def generate_rsa_key_pair(self, subsystem_name):
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Store the key pair in the system
        self.private_keys[subsystem_name] = private_key
        self.public_keys[subsystem_name] = public_key

        print(f"RSA key pair generated for {subsystem_name}")

    def get_public_key(self, subsystem_name):
        return self.public_keys[subsystem_name]

    def get_private_key(self, subsystem_name):
        return self.private_keys[subsystem_name]

    def revoke_keys(self, subsystem_name):
        if subsystem_name in self.private_keys:
            del self.private_keys[subsystem_name]
            del self.public_keys[subsystem_name]
            print(f"Keys revoked for {subsystem_name}")


# Diffie-Hellman Key Exchange
class DiffieHellmanKeyExchange:
    def __init__(self):
        # Generate parameters for Diffie-Hellman
        self.parameters = dh.generate_parameters(
            generator=2, key_size=2048, backend=default_backend()
        )

    def generate_private_key(self):
        return self.parameters.generate_private_key()

    def generate_shared_key(self, private_key, peer_public_key):
        shared_key = private_key.exchange(peer_public_key)
        # Derive a key from the shared secret using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"diffie-hellman key exchange",
            backend=default_backend(),
        ).derive(shared_key)
        return derived_key


# Secure Communication System
class SecureCommunication:
    def __init__(self, key_management):
        self.key_management = key_management

    def rsa_encrypt(self, message, public_key):
        ciphertext = public_key.encrypt(
            message,
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return ciphertext

    def rsa_decrypt(self, ciphertext, private_key):
        plaintext = private_key.decrypt(
            ciphertext,
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext

    def aes_encrypt(self, message, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        return iv + ciphertext

    def aes_decrypt(self, ciphertext, key):
        iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        return plaintext


# Simulate secure communication between systems
def simulate_communication():
    # Key Management System
    km = KeyManagement()

    # Generate RSA keys for systems A, B, and C
    km.generate_rsa_key_pair("System A")
    km.generate_rsa_key_pair("System B")
    km.generate_rsa_key_pair("System C")

    # Diffie-Hellman Key Exchange
    dhke = DiffieHellmanKeyExchange()

    # System A and System B establish shared keys via Diffie-Hellman
    private_key_a = dhke.generate_private_key()
    private_key_b = dhke.generate_private_key()

    public_key_a = private_key_a.public_key()
    public_key_b = private_key_b.public_key()

    shared_key_ab = dhke.generate_shared_key(private_key_a, public_key_b)
    shared_key_ba = dhke.generate_shared_key(private_key_b, public_key_a)

    # Secure Communication
    secure_comm = SecureCommunication(km)

    # RSA encryption between systems
    message = b"Secure financial report from System A"
    encrypted_message = secure_comm.rsa_encrypt(message, km.get_public_key("System B"))
    decrypted_message = secure_comm.rsa_decrypt(
        encrypted_message, km.get_private_key("System B")
    )

    print("Decrypted Message:", decrypted_message)

    # AES encryption using shared key
    secret_message = b"Procurement order from System A to System B"
    encrypted_secret_message = secure_comm.aes_encrypt(secret_message, shared_key_ab)
    decrypted_secret_message = secure_comm.aes_decrypt(
        encrypted_secret_message, shared_key_ba
    )

    print("Decrypted Secret Message:", decrypted_secret_message)


# Run the simulation
simulate_communication()

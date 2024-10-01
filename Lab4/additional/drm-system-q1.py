import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Tuple, Optional
import base64


class DRMSystem:
    def __init__(self, key_size: int = 2048, storage_dir: str = "drm_storage"):
        self.key_size = key_size
        self.storage_dir = storage_dir
        self.setup_storage()
        self.setup_logging()
        self.load_or_generate_master_keys()

    def setup_storage(self):
        # Create storage directories
        os.makedirs(self.storage_dir, exist_ok=True)
        os.makedirs(os.path.join(self.storage_dir, "content"), exist_ok=True)
        os.makedirs(os.path.join(self.storage_dir, "access_rights"), exist_ok=True)
        os.makedirs(os.path.join(self.storage_dir, "keys"), exist_ok=True)

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(os.path.join(self.storage_dir, "drm.log")),
                logging.StreamHandler(),
            ],
        )
        self.logger = logging.getLogger(__name__)

    def load_or_generate_master_keys(self):
        keys_file = os.path.join(self.storage_dir, "keys", "master_keys.json")
        if os.path.exists(keys_file):
            with open(keys_file, "r") as f:
                keys_data = json.load(f)
                latest_key = max(keys_data, key=lambda x: x["created_at"])
                if datetime.fromisoformat(latest_key["expires_at"]) > datetime.now():
                    self.master_public_key = serialization.load_pem_public_key(
                        latest_key["public_key"].encode()
                    )
                    self.master_private_key = serialization.load_pem_private_key(
                        latest_key["private_key"].encode(), password=None
                    )
                    return

        self.generate_new_master_keys()

    def generate_new_master_keys(self):
        self.logger.info(f"Generating new master keys with size {self.key_size}")
        self.master_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=self.key_size
        )
        self.master_public_key = self.master_private_key.public_key()

        # Serialize keys
        private_pem = self.master_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        public_pem = self.master_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        # Store keys
        keys_file = os.path.join(self.storage_dir, "keys", "master_keys.json")
        keys_data = []
        if os.path.exists(keys_file):
            with open(keys_file, "r") as f:
                keys_data = json.load(f)

        keys_data.append(
            {
                "public_key": public_pem,
                "private_key": private_pem,
                "created_at": datetime.now().isoformat(),
                "expires_at": (datetime.now() + timedelta(days=730)).isoformat(),
            }
        )

        with open(keys_file, "w") as f:
            json.dump(keys_data, f, indent=2)

        self.logger.info("New master keys generated and stored")

    def _generate_content_id(self) -> str:
        return base64.urlsafe_b64encode(os.urandom(16)).decode()

    def encrypt_content(self, content: bytes, creator_id: str) -> str:
        # Generate a unique key for this content
        content_key = Fernet.generate_key()
        f = Fernet(content_key)

        # Encrypt the content
        encrypted_content = f.encrypt(content)

        if isinstance(self.master_public_key, RSAPublicKey):
            encrypted_key = self.master_public_key.encrypt(
                content_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        else:
            raise TypeError("Unsupported key type for encryption")

        content_id = self._generate_content_id()
        content_data = {
            "creator_id": creator_id,
            "encrypted_content": base64.b64encode(encrypted_content).decode(),
            "content_key": base64.b64encode(encrypted_key).decode(),
            "created_at": datetime.now().isoformat(),
        }

        content_file = os.path.join(self.storage_dir, "content", f"{content_id}.json")
        with open(content_file, "w") as f:
            json.dump(content_data, f, indent=2)

        self.logger.info(f"Content encrypted and stored with ID {content_id}")
        return content_id

    def grant_access(self, content_id: str, customer_id: str, duration_days: int = 30):
        access_file = os.path.join(
            self.storage_dir, "access_rights", f"{content_id}.json"
        )
        access_data = {}
        if os.path.exists(access_file):
            with open(access_file, "r") as f:
                access_data = json.load(f)

        access_data[customer_id] = {
            "granted_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=duration_days)).isoformat(),
        }

        with open(access_file, "w") as f:
            json.dump(access_data, f, indent=2)

        self.logger.info(
            f"Access granted to customer {customer_id} for content {content_id}"
        )

    def revoke_access(self, content_id: str, customer_id: str):
        access_file = os.path.join(
            self.storage_dir, "access_rights", f"{content_id}.json"
        )
        if os.path.exists(access_file):
            with open(access_file, "r") as f:
                access_data = json.load(f)

            if customer_id in access_data:
                del access_data[customer_id]

                with open(access_file, "w") as f:
                    json.dump(access_data, f, indent=2)

        self.logger.info(
            f"Access revoked for customer {customer_id} to content {content_id}"
        )

    def can_access(self, content_id: str, customer_id: str) -> bool:
        access_file = os.path.join(
            self.storage_dir, "access_rights", f"{content_id}.json"
        )
        if not os.path.exists(access_file):
            return False

        with open(access_file, "r") as f:
            access_data = json.load(f)

        if customer_id not in access_data:
            return False

        expires_at = datetime.fromisoformat(access_data[customer_id]["expires_at"])
        return expires_at > datetime.now()

    def decrypt_content(self, content_id: str, customer_id: str) -> Optional[bytes]:
        if not self.can_access(content_id, customer_id):
            self.logger.warning(
                f"Access denied for customer {customer_id} to content {content_id}"
            )
            return None

        content_file = os.path.join(self.storage_dir, "content", f"{content_id}.json")
        with open(content_file, "r") as f:
            content_data = json.load(f)

        encrypted_content = base64.b64decode(content_data["encrypted_content"])
        encrypted_key = base64.b64decode(content_data["content_key"])

        # Decrypt the content key
        if isinstance(self.master_private_key, rsa.RSAPrivateKey):
            content_key = self.master_private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        else:
            raise TypeError("Unsupported key type for decryption")

        # Use the content key to decrypt the content
        f = Fernet(content_key)
        decrypted_content = f.decrypt(encrypted_content)

        self.logger.info(f"Content {content_id} decrypted for customer {customer_id}")
        return decrypted_content

    def revoke_master_key(self):
        self.generate_new_master_keys()
        self.logger.warning("Master key revoked and replaced")

    def scheduled_key_renewal(self):
        keys_file = os.path.join(self.storage_dir, "keys", "master_keys.json")
        if os.path.exists(keys_file):
            with open(keys_file, "r") as f:
                keys_data = json.load(f)
                latest_key = max(keys_data, key=lambda x: x["created_at"])
                if datetime.fromisoformat(
                    latest_key["expires_at"]
                ) <= datetime.now() + timedelta(days=30):
                    self.generate_new_master_keys()
                    self.logger.info("Scheduled key renewal completed")


# Example usage
if __name__ == "__main__":
    drm = DRMSystem(key_size=2048)

    # Example content creation
    content = b"This is some protected digital content"
    creator_id = "creator123"
    content_id = drm.encrypt_content(content, creator_id)

    # Grant access to a customer
    customer_id = "customer456"
    drm.grant_access(content_id, customer_id)

    # Customer accesses content
    decrypted_content = drm.decrypt_content(content_id, customer_id)
    if decrypted_content is not None:
        print(f"Decrypted content: {decrypted_content.decode()}")
    else:
        print("Failed to decrypt content.")

    # Revoke access
    drm.revoke_access(content_id, customer_id)

    # Scheduled maintenance
    drm.scheduled_key_renewal()

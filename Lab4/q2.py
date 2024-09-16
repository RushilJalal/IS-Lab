import random
import sympy
import os
from datetime import datetime, timedelta


class KeyManagement:
    def __init__(self):
        self.keys = {}
        self.log = []

    # Generate Rabin Key Pair
    def generate_rabin_key_pair(self, name, key_size=1024):
        # Generate two large primes p and q
        p = sympy.randprime(2 ** (key_size // 2 - 1), 2 ** (key_size // 2))
        q = sympy.randprime(2 ** (key_size // 2 - 1), 2 ** (key_size // 2))
        n = p * q

        # Save keys securely
        self.keys[name] = {
            "public_key": n,
            "private_key": (p, q),
            "created": datetime.now(),
            "renewal_date": datetime.now() + timedelta(days=365),
        }

        # Log the operation
        self.log_operation(f"Generated keys for {name}")
        return n, (p, q)

    # Secure Storage Example (simulated by saving to a secure location)
    def store_private_key_securely(self, name):
        if name in self.keys:
            # Encrypt and store the private key securely (This is a simulated secure store)
            # In practice, you'd encrypt this and store it in a secure database
            private_key = self.keys[name]["private_key"]
            with open(f"{name}_private_key.secure", "w") as file:
                file.write(str(private_key))
            self.log_operation(f"Private key securely stored for {name}")
        else:
            print(f"Error: No keys found for {name}")

    # Key Revocation
    def revoke_keys(self, name):
        if name in self.keys:
            del self.keys[name]
            os.remove(f"{name}_private_key.secure")
            self.log_operation(f"Revoked keys for {name}")
            print(f"Keys revoked for {name}")
        else:
            print(f"No keys to revoke for {name}")

    # Key Renewal
    def renew_keys(self):
        now = datetime.now()
        for name, data in self.keys.items():
            if data["renewal_date"] <= now:
                # Generate new keys
                print(f"Renewing keys for {name}...")
                self.generate_rabin_key_pair(name)
                self.store_private_key_securely(name)
                self.log_operation(f"Renewed keys for {name}")

    # Logging operations
    def log_operation(self, operation):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log.append(f"[{timestamp}] {operation}")
        print(f"Logged operation: {operation}")

    # View the logs for auditing
    def view_logs(self):
        print("Audit Logs:")
        for log_entry in self.log:
            print(log_entry)


# Simulating Key Management
km = KeyManagement()

# Key generation for a hospital
hospital_name = "CityHospital"
public_key, private_key = km.generate_rabin_key_pair(hospital_name, key_size=1024)

# Securely store the private key
km.store_private_key_securely(hospital_name)

# View logs
km.view_logs()

# Revoke keys example
km.revoke_keys(hospital_name)

# Renew keys for all hospitals (if past renewal date)
km.renew_keys()

# View logs after renewal
km.view_logs()

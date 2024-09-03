import hashlib
import time
import random
import string

# Function to generate random strings
def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Function to compute hash values
def compute_hashes(data):
    hashes = {
        'MD5': hashlib.md5(data.encode()).hexdigest(),
        'SHA-1': hashlib.sha1(data.encode()).hexdigest(),
        'SHA-256': hashlib.sha256(data.encode()).hexdigest()
    }
    return hashes

# Function to measure hash computation time and detect collisions
def analyze_hash_performance(strings):
    results = {
        'MD5': {'time': 0, 'collisions': set()},
        'SHA-1': {'time': 0, 'collisions': set()},
        'SHA-256': {'time': 0, 'collisions': set()}
    }
    
    hashes = {'MD5': {}, 'SHA-1': {}, 'SHA-256': {}}
    
    for s in strings:
        # Measure time for MD5
        start_time = time.time()
        md5_hash = hashlib.md5(s.encode()).hexdigest()
        results['MD5']['time'] += time.time() - start_time
        
        if md5_hash in hashes['MD5']:
            results['MD5']['collisions'].add(md5_hash)
        hashes['MD5'][md5_hash] = s
        
        # Measure time for SHA-1
        start_time = time.time()
        sha1_hash = hashlib.sha1(s.encode()).hexdigest()
        results['SHA-1']['time'] += time.time() - start_time
        
        if sha1_hash in hashes['SHA-1']:
            results['SHA-1']['collisions'].add(sha1_hash)
        hashes['SHA-1'][sha1_hash] = s
        
        # Measure time for SHA-256
        start_time = time.time()
        sha256_hash = hashlib.sha256(s.encode()).hexdigest()
        results['SHA-256']['time'] += time.time() - start_time
        
        if sha256_hash in hashes['SHA-256']:
            results['SHA-256']['collisions'].add(sha256_hash)
        hashes['SHA-256'][sha256_hash] = s
    
    return results

def main():
    # Generate a dataset of random strings
    num_strings = random.randint(50, 100)
    strings = [generate_random_string(random.randint(8, 20)) for _ in range(num_strings)]
    
    # Analyze hash performance
    performance_results = analyze_hash_performance(strings)
    
    # Print results
    for algorithm, result in performance_results.items():
        print(f"{algorithm}:")
        print(f"  Time taken for hashing: {result['time']:.10f} seconds")
        print(f"  Number of collisions: {len(result['collisions'])}")

if __name__ == "__main__":
    main()

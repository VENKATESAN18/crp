import random

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def lcm(a, b):
    return (a * b) // gcd(a, b)

def mod_inv(a, m):
    """Compute the modular inverse using the Extended Euclidean Algorithm."""
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def L(u, n):
    return (u - 1) // n

def is_prime(n):
    """Check if a number is prime using trial division."""
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def key_generation():
    """Generate public and private keys for Paillier encryption."""
    p = int(input("Enter a prime number p: "))
    q = int(input("Enter a prime number q: "))
    
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    if p == q:
        raise ValueError("p and q must be distinct.")
    
    n = p * q
    lambda_n = lcm(p - 1, q - 1)
    g = n + 1  # Standard choice for g in Paillier cryptosystem
    mu = mod_inv(L(pow(g, lambda_n, n * n), n), n)
    
    return (n, g), (lambda_n, mu)

def encrypt(m, public_key):
    """Encrypt a message m using the Paillier encryption scheme."""
    n, g = public_key
    r = random.randint(1, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)
    
    c = (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)
    return c

def decrypt(c, public_key, private_key):
    """Decrypt a ciphertext using the Paillier cryptosystem."""
    n, g = public_key
    lambda_n, mu = private_key
    m = (L(pow(c, lambda_n, n * n), n) * mu) % n
    return m

# Example Usage
if __name__ == "__main__":
    public_key, private_key = key_generation()
    message = int(input("Enter the message to encrypt: "))
    
    encrypted_message = encrypt(message, public_key)
    decrypted_message = decrypt(encrypted_message, public_key, private_key)
    
    print("\nOriginal Message:", message)
    print("Encrypted Message:", encrypted_message)
    print("Decrypted Message:", decrypted_message)
    
    if message == decrypted_message:
        print("\nSuccess! The decrypted message matches the original.")
    else:
        print("\nError! Decryption failed.")




#Enter a prime number p: 7
#Enter a prime number q: 11
#Enter the message to encrypt: 15

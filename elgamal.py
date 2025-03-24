import random

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inv(a, m):
    """Compute the modular inverse using the Extended Euclidean Algorithm."""
    m0, x0, x1 = m, 0, 1
    if gcd(a, m) != 1:
        raise ValueError("No modular inverse exists for the given numbers.")
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def is_prime(n):
    """Check if a number is prime using trial division."""
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def key_generation():
    """Generate public and private keys for ElGamal encryption."""
    p = int(input("Enter a prime number p: "))
    g = int(input("Enter a generator g: "))
    
    if not is_prime(p):
        raise ValueError("p must be a prime number.")
    if g <= 1 or g >= p:
        raise ValueError("g must be between 2 and p-1.")

    x = random.randint(1, p - 2)  # Private key (1 ≤ x ≤ p-2)
    y = pow(g, x, p)  # Public key component y = g^x mod p
    
    print("\nPublic Key (p, g, y):", (p, g, y))
    print("Private Key (x):", x)

    return (p, g, y), x  # Public and private keys

def encrypt(m, public_key):
    """Encrypt a message m using ElGamal encryption."""
    p, g, y = public_key
    if not (0 < m < p):  
        raise ValueError("Message must be within the range [1, p-1].")

    while True:
        k = random.randint(1, p - 2)  # Choose a random k
        if gcd(k, p - 1) == 1:  # Ensure k is coprime with (p-1)
            break

    c1 = pow(g, k, p)  # c1 = g^k mod p
    c2 = (m * pow(y, k, p)) % p  # c2 = m * y^k mod p

    return c1, c2

def decrypt(ciphertext, private_key, public_key):
    """Decrypt an ElGamal ciphertext."""
    p, g, y = public_key
    x = private_key
    c1, c2 = ciphertext

    s = pow(c1, x, p)  # Compute shared secret: s = c1^x mod p
    s_inv = mod_inv(s, p)  # Compute modular inverse of s
    m = (c2 * s_inv) % p  # Compute original message

    return m

# Example Usage
if __name__ == "__main__":
    public_key, private_key = key_generation()
    message = int(input("\nEnter the message to encrypt: "))
    
    encrypted_message = encrypt(message, public_key)
    print("\nEncrypted Message:", encrypted_message)

    decrypted_message = decrypt(encrypted_message, private_key, public_key)
    print("Decrypted Message:", decrypted_message)

    if message == decrypted_message:
        print("\nSuccess! The decrypted message matches the original.")
    else:
        print("\nError! Decryption failed.")



#Enter a prime number p: 23
#Enter a generator g: 5

#Public Key (p, g, y): (23, 5, 7)
#Private Key (x): 4

#Enter the message to encrypt: 9

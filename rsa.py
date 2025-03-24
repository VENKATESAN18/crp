import random

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0  # Ensures the modular inverse is positive
    return x1

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def key_generation():
    p = int(input("Enter a prime number p: "))
    q = int(input("Enter a prime number q: "))

    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    if p == q:
        raise ValueError("p and q must be distinct.")

    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Common public exponent
    e = 65537
    if gcd(e, phi_n) != 1:
        raise ValueError("Chosen e is not coprime with phi(n). Choose different primes.")

    d = mod_inv(e, phi_n)

    return (n, e), (n, d)

def encrypt(m, public_key):
    n, e = public_key
    return pow(m, e, n)

def decrypt(c, private_key):
    n, d = private_key
    return pow(c, d, n)

# Example Usage
public_key, private_key = key_generation()

message = int(input("Enter the message to encrypt: "))
if message <= 0 or message >= public_key[0]:
    raise ValueError("Message must be between 1 and n-1")

encrypted_message = encrypt(message, public_key)
decrypted_message = decrypt(encrypted_message, private_key)

print("\nOriginal Message:", message)
print("Encrypted Message:", encrypted_message)
print("Decrypted Message:", decrypted_message)


#Enter a prime number p: 61
#Enter a prime number q: 53
#Enter the message to encrypt: 42

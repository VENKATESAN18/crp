def power(base, exponent, modulus):
    result = 1
    base = base % modulus  # Ensure base is within modulus
    while exponent > 0:
        if exponent % 2 == 1:  # If exponent is odd, multiply base with result
            result = (result * base) % modulus
        exponent = exponent >> 1  # Divide exponent by 2
        base = (base * base) % modulus  # Square the base
    return result

def main():
    print("Diffie-Hellman Multiparty Key Exchange")

    num_parties = int(input("Enter the number of parties: "))
    prime = int(input("Enter a prime number (p): "))
    generator = int(input("Enter a generator (g): "))

    private_keys = []
    for i in range(num_parties):
        private_key = int(input(f"Enter private key for Party {i+1}: "))
        private_keys.append(private_key)

    print("\nComputing intermediate values...")

    intermediate_values = []
    for i in range(num_parties):
        intermediate = power(generator, private_keys[i], prime)
        intermediate_values.append(intermediate)
        print(f"Party {i+1} computes and shares: {intermediate}")

    print("\nComputing shared secret keys...")

    final_keys = []
    for i in range(num_parties):
        shared_secret = intermediate_values[i]
        for j in range(num_parties - 1):
            next_party = (i + j + 1) % num_parties
            shared_secret = power(intermediate_values[next_party], shared_secret, prime)

        final_keys.append(shared_secret)
        print(f"Party {i+1}'s computed shared secret: {shared_secret}")

    if all(key == final_keys[0] for key in final_keys):
        print("\nSuccess! All parties have computed the same shared secret key.")
    else:
        print("\nError! The computed shared secret keys do not match.")

if __name__ == "__main__":
    main()


#Enter the number of parties: 3
#Enter a prime number (p): 23
#Enter a generator (g): 5
#Enter private key for Party 1: 6
#Enter private key for Party 2: 15
#Enter private key for Party 3: 10

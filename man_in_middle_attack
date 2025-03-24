def power(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result


def main():
    print("Diffie-Hellman Man-in-the-Middle Attack Simulation")

    # System parameters - shared by all parties
    prime = int(input("Enter the prime number (p): "))
    generator = int(input("Enter the generator (g): "))

    # Alice's private key
    alice_private = int(input("Enter Alice's private key: "))

    # Bob's private key
    bob_private = int(input("Enter Bob's private key: "))

    # Mallory's (attacker) private keys - one for communicating with Alice, one for Bob
    mallory_private_for_alice = int(input("Enter Mallory's private key for Alice: "))
    mallory_private_for_bob = int(input("Enter Mallory's private key for Bob: "))

    print("\n--- Normal Exchange (without MITM) ---")
    # What would happen normally
    alice_public = power(generator, alice_private, prime)
    bob_public = power(generator, bob_private, prime)

    print(f"Alice computes and sends public value: {alice_public}")
    print(f"Bob computes and sends public value: {bob_public}")

    alice_shared_key = power(bob_public, alice_private, prime)
    bob_shared_key = power(alice_public, bob_private, prime)

    print(f"Alice's shared key: {alice_shared_key}")
    print(f"Bob's shared key: {bob_shared_key}")

    if alice_shared_key == bob_shared_key:
        print("Without MITM: Alice and Bob have established the same shared key\n")
    else:
        print("Without MITM: Key establishment failed\n")

    print("\n--- With MITM Attack ---")
    # What happens with Mallory in the middle
    alice_public = power(generator, alice_private, prime)
    bob_public = power(generator, bob_private, prime)

    print(f"Alice computes and sends public value: {alice_public}")
    print(f"Bob computes and sends public value: {bob_public}")

    # Mallory intercepts these values and doesn't pass them along
    # Instead, Mallory generates her own values to send to Alice and Bob
    mallory_public_for_alice = power(generator, mallory_private_for_alice, prime)
    mallory_public_for_bob = power(generator, mallory_private_for_bob, prime)

    print(f"Mallory intercepts and sends to Alice: {mallory_public_for_bob}")
    print(f"Mallory intercepts and sends to Bob: {mallory_public_for_alice}")

    # Alice and Bob compute their keys using Mallory's values
    alice_key_with_mallory = power(mallory_public_for_bob, alice_private, prime)
    bob_key_with_mallory = power(mallory_public_for_alice, bob_private, prime)

    # Mallory computes two shared keys - one for Alice, one for Bob
    mallory_key_with_alice = power(alice_public, mallory_private_for_bob, prime)
    mallory_key_with_bob = power(bob_public, mallory_private_for_alice, prime)

    print(f"\nAlice's computed key: {alice_key_with_mallory}")
    print(f"Mallory's key with Alice: {mallory_key_with_alice}")
    print(f"Bob's computed key: {bob_key_with_mallory}")
    print(f"Mallory's key with Bob: {mallory_key_with_bob}")

    # Verification
    if alice_key_with_mallory == mallory_key_with_alice:
        print("\nMallory can decrypt all messages from Alice")
    else:
        print("\nMallory cannot decrypt Alice's messages")

    if bob_key_with_mallory == mallory_key_with_bob:
        print("Mallory can decrypt all messages from Bob")
    else:
        print("Mallory cannot decrypt Bob's messages")

    if alice_key_with_mallory != bob_key_with_mallory:
        print("MITM attack successful: Alice and Bob have different keys and are unaware")

    # Sample message exchange
    print("\n--- Sample Message Exchange ---")

    alice_message = input("Enter Alice's message to Bob: ")
    print(f"Alice encrypts '{alice_message}' with key {alice_key_with_mallory}")
    print(f"Mallory intercepts and decrypts using key {mallory_key_with_alice}")
    print(f"Mallory re-encrypts with key {mallory_key_with_bob} and forwards to Bob")
    print(f"Bob decrypts using key {bob_key_with_mallory}")


if __name__ == "__main__":
    main()

#Enter the prime number (p): 23
#Enter the generator (g): 5
#Enter Alice's private key: 6
#Enter Bob's private key: 15
#Enter Mallory's private key for Alice: 9
#Enter Mallory's private key for Bob: 4
#Enter Alice's message to Bob: Hello Bob!

# AES Implementation from scratch
# This implements AES-128 (128-bit key, 10 rounds)

# AES S-box (pre-computed substitution table)
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Inverse S-box (for decryption)
INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Round constants used in key expansion
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# GF(2^8) multiplication for MixColumns
def gf_mul(a, b):
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b  # AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p & 0xff

# Key expansion function
def key_expansion(key):
    """
    Expands the cipher key into the key schedule.
    For AES-128, the key is 16 bytes (128 bits) and expands to 11 round keys (44 words)
    """
    key_words = [0] * 44
    
    # First, copy the original key
    for i in range(4):
        key_words[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3]
    
    # Expand the key
    for i in range(4, 44):
        temp = key_words[i-1]
        if i % 4 == 0:
            # RotWord operation
            temp = ((temp << 8) | ((temp >> 24) & 0xff)) & 0xffffffff
            
            # SubWord operation
            temp = (SBOX[(temp >> 24) & 0xff] << 24 |
                   SBOX[(temp >> 16) & 0xff] << 16 |
                   SBOX[(temp >> 8) & 0xff] << 8 |
                   SBOX[temp & 0xff])
            
            # XOR with round constant
            temp ^= (RCON[i // 4 - 1] << 24)
        
        key_words[i] = key_words[i-4] ^ temp
    
    # Convert 32-bit words to byte array
    expanded_key = bytearray(176)  # 11 round keys * 16 bytes
    for i in range(44):
        expanded_key[4*i] = (key_words[i] >> 24) & 0xff
        expanded_key[4*i+1] = (key_words[i] >> 16) & 0xff
        expanded_key[4*i+2] = (key_words[i] >> 8) & 0xff
        expanded_key[4*i+3] = key_words[i] & 0xff
    
    return expanded_key

# SubBytes transformation
def sub_bytes(state):
    for i in range(16):
        state[i] = SBOX[state[i]]
    return state

# Inverse SubBytes transformation
def inv_sub_bytes(state):
    for i in range(16):
        state[i] = INV_SBOX[state[i]]
    return state

# ShiftRows transformation
def shift_rows(state):
    # Convert to 4x4 grid (column-major order)
    grid = [[state[i*4+j] for i in range(4)] for j in range(4)]
    
    # Perform ShiftRows
    for i in range(4):
        grid[i] = grid[i][i:] + grid[i][:i]
    
    # Convert back to flat array
    for i in range(4):
        for j in range(4):
            state[i+j*4] = grid[j][i]
    
    return state

# Inverse ShiftRows transformation
def inv_shift_rows(state):
    # Convert to 4x4 grid (column-major order)
    grid = [[state[i*4+j] for i in range(4)] for j in range(4)]
    
    # Perform Inverse ShiftRows
    for i in range(4):
        grid[i] = grid[i][-i:] + grid[i][:-i]
    
    # Convert back to flat array
    for i in range(4):
        for j in range(4):
            state[i+j*4] = grid[j][i]
    
    return state

# MixColumns transformation
def mix_columns(state):
    for i in range(0, 16, 4):
        col = state[i:i+4]
        
        s0 = gf_mul(col[0], 2) ^ gf_mul(col[1], 3) ^ col[2] ^ col[3]
        s1 = col[0] ^ gf_mul(col[1], 2) ^ gf_mul(col[2], 3) ^ col[3]
        s2 = col[0] ^ col[1] ^ gf_mul(col[2], 2) ^ gf_mul(col[3], 3)
        s3 = gf_mul(col[0], 3) ^ col[1] ^ col[2] ^ gf_mul(col[3], 2)
        
        state[i:i+4] = [s0, s1, s2, s3]
    
    return state

# Inverse MixColumns transformation
def inv_mix_columns(state):
    for i in range(0, 16, 4):
        col = state[i:i+4]
        
        s0 = gf_mul(col[0], 0x0e) ^ gf_mul(col[1], 0x0b) ^ gf_mul(col[2], 0x0d) ^ gf_mul(col[3], 0x09)
        s1 = gf_mul(col[0], 0x09) ^ gf_mul(col[1], 0x0e) ^ gf_mul(col[2], 0x0b) ^ gf_mul(col[3], 0x0d)
        s2 = gf_mul(col[0], 0x0d) ^ gf_mul(col[1], 0x09) ^ gf_mul(col[2], 0x0e) ^ gf_mul(col[3], 0x0b)
        s3 = gf_mul(col[0], 0x0b) ^ gf_mul(col[1], 0x0d) ^ gf_mul(col[2], 0x09) ^ gf_mul(col[3], 0x0e)
        
        state[i:i+4] = [s0, s1, s2, s3]
    
    return state

# AddRoundKey transformation
def add_round_key(state, round_key):
    for i in range(16):
        state[i] ^= round_key[i]
    return state

# AES Encryption function
def aes_encrypt_block(plaintext, key):
    """
    Encrypts a single 16-byte block using AES-128.
    
    Args:
        plaintext (bytes): 16-byte plaintext block
        key (bytes): 16-byte key
    
    Returns:
        bytes: 16-byte ciphertext block
    """
    if len(plaintext) != 16:
        raise ValueError("Plaintext block must be 16 bytes")
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    
    # Key expansion
    expanded_key = key_expansion(key)
    
    # Initialize state with plaintext
    state = bytearray(plaintext)
    
    # Initial round
    state = add_round_key(state, expanded_key[0:16])
    
    # Main rounds
    for round_num in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, expanded_key[round_num*16:(round_num+1)*16])
    
    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, expanded_key[160:176])
    
    return bytes(state)

# AES Decryption function
def aes_decrypt_block(ciphertext, key):
    """
    Decrypts a single 16-byte block using AES-128.
    
    Args:
        ciphertext (bytes): 16-byte ciphertext block
        key (bytes): 16-byte key
    
    Returns:
        bytes: 16-byte plaintext block
    """
    if len(ciphertext) != 16:
        raise ValueError("Ciphertext block must be 16 bytes")
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    
    # Key expansion
    expanded_key = key_expansion(key)
    
    # Initialize state with ciphertext
    state = bytearray(ciphertext)
    
    # Initial round
    state = add_round_key(state, expanded_key[160:176])
    
    # Main rounds
    for round_num in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, expanded_key[round_num*16:(round_num+1)*16])
        state = inv_mix_columns(state)
    
    # Final round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, expanded_key[0:16])
    
    return bytes(state)

# PKCS#7 padding
def pkcs7_pad(data, block_size=16):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

# AES Encryption in ECB mode
def aes_encrypt_ecb(plaintext, key):
    """
    Encrypts plaintext using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        plaintext (bytes): Plaintext data of any length
        key (bytes): 16-byte key
    
    Returns:
        bytes: Encrypted data
    """
    padded_plaintext = pkcs7_pad(plaintext)
    ciphertext = bytearray()
    
    # Process each block
    for i in range(0, len(padded_plaintext), 16):
        block = padded_plaintext[i:i+16]
        encrypted_block = aes_encrypt_block(block, key)
        ciphertext.extend(encrypted_block)
    
    return bytes(ciphertext)

# AES Decryption in ECB mode
def aes_decrypt_ecb(ciphertext, key):
    """
    Decrypts ciphertext using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        ciphertext (bytes): Encrypted data (must be multiple of 16 bytes)
        key (bytes): 16-byte key
    
    Returns:
        bytes: Decrypted data
    """
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes")
    
    plaintext = bytearray()
    
    # Process each block
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = aes_decrypt_block(block, key)
        plaintext.extend(decrypted_block)
    
    # Remove padding
    return pkcs7_unpad(plaintext)

# AES Encryption in CBC mode
def aes_encrypt_cbc(plaintext, key, iv):
    """
    Encrypts plaintext using AES-128 in CBC mode with PKCS#7 padding.
    
    Args:
        plaintext (bytes): Plaintext data of any length
        key (bytes): 16-byte key
        iv (bytes): 16-byte initialization vector
    
    Returns:
        bytes: Encrypted data
    """
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    
    padded_plaintext = pkcs7_pad(plaintext)
    ciphertext = bytearray()
    prev_block = iv
    
    # Process each block
    for i in range(0, len(padded_plaintext), 16):
        block = padded_plaintext[i:i+16]
        
        # XOR with previous ciphertext block (or IV for first block)
        xored_block = bytearray(16)
        for j in range(16):
            xored_block[j] = block[j] ^ prev_block[j]
        
        encrypted_block = aes_encrypt_block(xored_block, key)
        ciphertext.extend(encrypted_block)
        prev_block = encrypted_block
    
    return bytes(ciphertext)

# AES Decryption in CBC mode
def aes_decrypt_cbc(ciphertext, key, iv):
    """
    Decrypts ciphertext using AES-128 in CBC mode with PKCS#7 padding.
    
    Args:
        ciphertext (bytes): Encrypted data (must be multiple of 16 bytes)
        key (bytes): 16-byte key
        iv (bytes): 16-byte initialization vector
    
    Returns:
        bytes: Decrypted data
    """
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    
    plaintext = bytearray()
    prev_block = iv
    
    # Process each block
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = aes_decrypt_block(block, key)
        
        # XOR with previous ciphertext block (or IV for first block)
        xored_block = bytearray(16)
        for j in range(16):
            xored_block[j] = decrypted_block[j] ^ prev_block[j]
        
        plaintext.extend(xored_block)
        prev_block = block
    
    # Remove padding
    return pkcs7_unpad(plaintext)

# Example usage
if __name__ == "__main__":
    import os
    
    # Generate a random 16-byte key and IV
    key = os.urandom(16)
    iv = os.urandom(16)
    
    # Original message
    message = b"This is a test message for AES encryption!"
    
    print("Original message:", message.decode('utf-8'))
    
    # ECB mode
    encrypted_ecb = aes_encrypt_ecb(message, key)
    decrypted_ecb = aes_decrypt_ecb(encrypted_ecb, key)
    
    print("\nECB Mode:")
    print("Encrypted (hex):", encrypted_ecb.hex())
    print("Decrypted:", decrypted_ecb.decode('utf-8'))
    
    # CBC mode
    encrypted_cbc = aes_encrypt_cbc(message, key, iv)
    decrypted_cbc = aes_decrypt_cbc(encrypted_cbc, key, iv)
    
    print("\nCBC Mode:")
    print("Encrypted (hex):", encrypted_cbc.hex())
    print("Decrypted:", decrypted_cbc.decode('utf-8'))



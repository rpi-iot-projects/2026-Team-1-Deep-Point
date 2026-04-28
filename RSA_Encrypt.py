import json
from pathlib import Path
import Number_Package as npkg
import random
import time

# based on lab6 code
def RSA_keygen():
    gap = random.randint(2**27, 2**29)
    p = npkg.find_prime_smaller_than_k(2**31 - gap)
    q = npkg.find_prime_greater_than_k(2**31 + gap)
    e = 65537
    N = p * q
    phi = (p - 1) * (q - 1)
    d = npkg.mult_inv_mod_N(e, phi)
    return e, d, N

def RSA_encrypt(m, e, N):
    return npkg.exp_mod(m, e, N)

def RSA_decrypt(c, d, N):
    return npkg.exp_mod(c, d, N)

def encrypt_small_zip(zip_in_path, encrypted_out_path, e, N):
    data = Path(zip_in_path).read_bytes()

    # max bytes per block must satisfy block_int < N
    block_size = max(1, (N.bit_length() - 1) // 8)

    encrypted_blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        m = int.from_bytes(block, byteorder="big")
        c = RSA_encrypt(m, e, N)
        encrypted_blocks.append({
            "cipher": str(c),
            "length": len(block)
        })

    payload = {
        "N": str(N),
        "block_size": block_size,
        "blocks": encrypted_blocks
    }

    with open(encrypted_out_path, "w") as f:
        json.dump(payload, f)

def decrypt_small_zip(encrypted_in_path, zip_out_path, d, N):
    with open(encrypted_in_path, "r") as f:
        payload = json.load(f)

    out = bytearray()

    for item in payload["blocks"]:
        c = int(item["cipher"])
        block_len = item["length"]
        m = RSA_decrypt(c, d, N)
        block = m.to_bytes(block_len, byteorder="big")
        out.extend(block)

    Path(zip_out_path).write_bytes(out)

if __name__ == "__main__":
    zip_file = "/Users/adithyavijayan/Documents/Security/depth-selected.zip"
    encrypted_file = "depth-selected_encrypted.json"
    recovered_zip = "depth-selected_recovered.zip"

    # Time key generation
    t0 = time.perf_counter()
    e, d, N = RSA_keygen()
    t_keygen = time.perf_counter() - t0

    # Time encryption
    t0 = time.perf_counter()
    encrypt_small_zip(zip_file, encrypted_file, e, N)
    t_enc = time.perf_counter() - t0

    # Time decryption
    t0 = time.perf_counter()
    decrypt_small_zip(encrypted_file, recovered_zip, d, N)
    t_dec = time.perf_counter() - t0

    # File size and integrity check
    from pathlib import Path
    file_size = Path(zip_file).stat().st_size
    original = Path(zip_file).read_bytes()
    recovered = Path(recovered_zip).read_bytes()
    identical = original == recovered

    print("=" * 60)
    print("RSA Encryption PoC")
    print("=" * 60)
    print(f"Input file:          {zip_file}")
    print(f"File size:           {file_size:,} bytes ({file_size/1024:.1f} KB)")
    print(f"Modulus N bit length: {N.bit_length()} bits")
    print(f"Block size:          {(N.bit_length() - 1) // 8} bytes")
    print(f"Key generation:      {t_keygen*1000:.3f} ms")
    print(f"Encryption time:     {t_enc*1000:.3f} ms  ({t_enc:.3f} s)")
    print(f"Decryption time:     {t_dec*1000:.3f} ms  ({t_dec:.3f} s)")
    if t_enc > 0:
        throughput = file_size / t_enc / 1024 / 1024
        print(f"Encrypt throughput:  {throughput:.4f} MB/s")
    print(f"Round-trip match:    {identical}")
    print("=" * 60)
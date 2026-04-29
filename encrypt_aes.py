"""
AES-128-GCM encryption proof-of-concept for DeepPoint.
Mirrors the structure of ecrypt.py (RSA version) for side-by-side comparison.

Design choices:
- Uses Python's `cryptography` library (audited, constant-time) rather than a
  from-scratch implementation. AES is error-prone to implement correctly (timing
  side-channels, S-box bugs, key-schedule mistakes), and the pedagogical value
  of AES lies in its *use*, not in re-implementing its finite-field arithmetic.
- AES-128 in Galois/Counter Mode (GCM): provides both confidentiality AND
  authenticated integrity via a built-in GMAC tag. No separate MAC needed.
- 96-bit IV (NIST SP 800-38D recommended length for GCM).
"""

import json
import os
import time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def AES_keygen():
    """Generate a random 128-bit AES key."""
    return AESGCM.generate_key(bit_length=128)


def encrypt_zip_aes(zip_in_path, encrypted_out_path, key):
    """AES-128-GCM encrypt an entire file in one shot.

    Unlike RSA, AES handles arbitrary-length data natively (via CTR mode inside
    GCM), so no block-by-block loop is needed.
    """
    data = Path(zip_in_path).read_bytes()

    aesgcm = AESGCM(key)
    iv = os.urandom(12)  # 96-bit IV per NIST SP 800-38D
    # encrypt() returns ciphertext || 16-byte GMAC auth tag concatenated
    ciphertext_and_tag = aesgcm.encrypt(iv, data, associated_data=None)

    payload = {
        "scheme": "AES-128-GCM",
        "iv_hex": iv.hex(),
        "ciphertext_hex": ciphertext_and_tag.hex(),
    }

    with open(encrypted_out_path, "w") as f:
        json.dump(payload, f)


def decrypt_zip_aes(encrypted_in_path, zip_out_path, key):
    """Decrypt and verify the GCM authentication tag.

    If any bit of the ciphertext or IV has been tampered with, AESGCM.decrypt
    raises InvalidTag and refuses to return any plaintext. This is the
    authenticated-encryption guarantee that plain RSA does not provide.
    """
    with open(encrypted_in_path, "r") as f:
        payload = json.load(f)

    iv = bytes.fromhex(payload["iv_hex"])
    ciphertext_and_tag = bytes.fromhex(payload["ciphertext_hex"])

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext_and_tag, associated_data=None)

    Path(zip_out_path).write_bytes(plaintext)


# ---------------------------------------------------------------------------
# Example usage with timing comparison vs. the RSA implementation
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    zip_file = "/Users/adithyavijayan/Documents/Security/depth-selected.zip"

    encrypted_file = "depth-selected_encrypted_aes.json"
    recovered_zip = "depth-selected_recovered_aes.zip"

    # Key generation
    t0 = time.perf_counter()
    key = AES_keygen()
    t_keygen = time.perf_counter() - t0

    # Encryption
    t0 = time.perf_counter()
    encrypt_zip_aes(zip_file, encrypted_file, key)
    t_enc = time.perf_counter() - t0

    # Decryption
    t0 = time.perf_counter()
    decrypt_zip_aes(encrypted_file, recovered_zip, key)
    t_dec = time.perf_counter() - t0

    # Round-trip integrity check
    original = Path(zip_file).read_bytes()
    recovered = Path(recovered_zip).read_bytes()
    identical = original == recovered

    file_size_bytes = len(original)

    print("=" * 60)
    print("AES-128-GCM Encryption PoC")
    print("=" * 60)
    print(f"Input file:          {zip_file}")
    print(f"File size:           {file_size_bytes:,} bytes "
          f"({file_size_bytes / 1024:.1f} KB)")
    print(f"Key generation:      {t_keygen * 1000:.3f} ms")
    print(f"Encryption time:     {t_enc * 1000:.3f} ms")
    print(f"Decryption time:     {t_dec * 1000:.3f} ms")
    throughput = file_size_bytes / t_enc / 1024 / 1024 if t_enc > 0 else float("inf")
    print(f"Encrypt throughput:  {throughput:.2f} MB/s")
    print(f"Round-trip match:    {identical}")
    print(f"Encrypted file:      {encrypted_file}")
    print(f"Recovered file:      {recovered_zip}")
    print("=" * 60)

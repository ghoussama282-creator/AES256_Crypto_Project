# AES-256 File Encryption System
Professional Python implementation of AES-256 in CBC mode for secure file encryption.

## Features
- PBKDF2 Key Derivation (600,000 iterations)
- AES-256-CBC Encryption
- SHA-256 Integrity Verification
- CSPRNG Salt and IV generation

## Threat Model & Security Analysis

1. Adversary Model
We assume an attacker who has:
Offline Access: Access to the encrypted .enc files.
Computational Resources: Capability to perform large-scale brute-force attacks.

2. Security Guarantees
Confidentiality: Provided by AES-256, ensuring that without the correct password, the plaintext remains inaccessible.
Integrity: Provided by SHA-256 hashing. If an attacker modifies even a single bit of the ciphertext, the decryption process will detect the mismatch and abort.
Brute-force Resistance: Provided by PBKDF2 with 600,000 iterations, making it computationally expensive for an attacker to test millions of passwords.

3. Identified Risks & Mitigations (Narrative Analysis)
In this implementation, we have addressed several critical cryptographic vulnerabilities through strategic design choices:

Resistance to Dictionary and Brute-force Attacks: Standard passwords often lack the entropy required for high-level encryption. To mitigate the risk of automated guessing or dictionary attacks, the system employs PBKDF2. By setting the iteration count to 600,000, we significantly increase the "work factor," making it computationally expensive and time-consuming for an adversary to test candidate passwords.

Defense Against Rainbow Table Attacks: A common threat in cryptography is the use of pre-computed hash tables (Rainbow Tables). We neutralize this risk by generating a unique 128-bit random Salt for every encryption session. This ensures that even if two files use the same password, their derived keys will be entirely different, rendering pre-computed tables useless.

Prevention of Pattern Recognition (Semantic Security): Using block ciphers like AES can sometimes reveal patterns in the ciphertext if the same data is encrypted twice. To achieve semantic security, we utilize a unique Initialization Vector (IV) for each file. This ensures that identical plaintexts result in completely different ciphertexts, preventing any form of pattern analysis by an observer.

Mitigation of Bit-Flipping and Tampering: Without integrity checks, an attacker could modify the ciphertext (Bit-flipping) to alter the decrypted message. We have mitigated this by integrating a SHA-256 Hash verification layer. The system validates the file's integrity before final output, ensuring that any unauthorized modification is detected and the process is aborted.

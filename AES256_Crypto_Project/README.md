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

3. Identified Risks & Mitigations
Threat                      Mitigation
Dictionary Attacks          Use of high-iteration PBKDF2 to slow down password guessing.
Rainbow Table Attacks       Unique 128-bit Salt for every encryption session.
Pattern Recognition         Unique IV (Initialization Vector) for every file, ensuring different ciphertexts for identical files.
Padding Oracle Attacks      Mitigation via integrity check before final processing (Future improvement: AES-GCM).

***The project is a final capstone project of rustcamp.***

### Secret Viewer Application

A secure web application written in Rust that allows users to create secrets that can be viewed a limited number of times and/or expire after a time-to-live (TTL).

Secrets are encrypted at rest using modern cryptography and optionally protected with a passphrase.

### Features

- End-to-end encryption using ChaCha20-Poly1305
- Secrets automatically expire based on TTL or maximum views
- Fully asynchronous backend using Axum and sqlx with PostgreSQL
- REST API for creating and retrieving secrets
- Simple web interface to view secrets with react.js
- Secure key handling using the zeroize crate

### How It Works

- Create a Message: Write a message you wish to send.
- Set Expiration and Lifetime: Choose how long the message will be available before it expires and whether it can be viewed only once.
- Optionally protect the secret with a passphrase. The passphrase will be required to view the secret.
- In case to opt without the passphrase, the decryption key will be generated and will be required to view the secret.
- Send the Message: Once sent, the link will be generated to access the message. The message can only be viewed specified number of times, once by default.
- Automatic Deletion: After being viewed or after expiration, the message is permanently deleted.

### Technology used:
- **Axum** crate for server
- **PostgresQL** for DB 
- **Tracing** crate for logging
- **Encryption** is done via:
  - `chacha20poly1305`(AEAD cipher)
  - `hkdf` (key derivation)
  - `zeroize` (secure key erasure)
  

### How the encryption works.
- There are two encryption modes:
  1. Passphrase-based encryption - when user protects the secret with a passphrase.
  2. Ephemeral encryption - when there is no passphrase.

### Case 1. Passphrase-based encryption.
- User's passphrase derives a key using HKDF (Sha-256) bound to a unique secret ID. 
- The passphrase is not directly used as a key. Instead it is fed into HKDF with a context: secret_id UUID.
- This ensures that even if two users have the same passphrase, they get different derived keys for different secrets.
- **Encryption**:
  - A random 96-bit nonce is generated securely (OsRng = system entropy).
  - ChaCha20Poly1305 encrypts the plain text and appends the authentication tag.
  - The nonce and ciphertext are concatenated and Base64-encoded. 
- **Decryption**:
  - The nonce is extracted from the first 12 bytes of the decoded data.
  - The ciphertext is the remaining bytes of the decoded data.
  - The key is rederived from the passphrase and secret_id UUID.
  - Attempt to decrypt. If anything (ciphertext, nonce, tag) was modified - decryption failed.

### Case 2. Ephemeral encryption.
- A random 256-bit key is generated.
- **Encryption**:
  - The plain text is encrypted with a random nonce.
  - Returns:
    - Encrypted Base64 data 
    - Base64 encoded decryption key (user must keep it).
  - Zero-knowldedge: The backend does not store the key - only the ciphertext.
  - The backend can's decrypt the data itself.
- **Decryption**:
- User provides the Base64-encoded key 
- The ciphertext is decoded, nonce extracted and decrypted.  
- The encyption key is random and unique per secret
- The keys are erased after use (`zeroize` crate)

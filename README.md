***The project is a final capstone project of rustcamp.***

### Secret Viewer Application

A secure web application written in Rust that allows users to create secrets that can be viewed a limited number of times and/or expire after a time-to-live (TTL).

Secrets are encrypted at rest using modern cryptography and optionally protected with a passphrase.

### Features

- End-to-end encryption using ChaCha20-Poly1305.
- Optional passphrase protection using Argon2 hashing.
- Secrets expire automatically based on TTL or maximum views.
- Fully asynchronous, using sqlx with PostgreSQL.
- REST API for creating and retrieving secrets.
- Web interface to view secrets.


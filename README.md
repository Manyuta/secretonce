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

### How It Works

- Create a Message: Write a message you wish to send.
- Set Expiration and Lifetime: Choose how long the message will be available before it expires and whether it can be viewed only once.
- Send the Message: Once sent, the link will be generated to access the message. The message can only be viewed specified number of times, once by default.
- Automatic Deletion: After being viewed or after expiration, the message is permanently deleted.





Usage
Start Receiver:

python secure_transfer.py receive 9000 mypassword

Send File:

python secure_transfer.py send secret.txt 127.0.0.1 9000 mypassword

 Notes

    This tool uses AES-CBC with PKCS7 padding.

    IV is randomly generated and prepended to encrypted data.

    Password is used to derive encryption key via PBKDF2.

    Not intended for large-scale or production use without improvements (e.g., authenticated encryption, proper key exchange, TLS).


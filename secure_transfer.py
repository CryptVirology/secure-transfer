import os
import socket
import argparse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode

BUFFER_SIZE = 4096
SALT = b'secure_salt'  # In production, use a random salt per session

def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(filepath: str, key: bytes) -> bytes:
    with open(filepath, 'rb') as f:
        data = f.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted  # Prepend IV to encrypted data

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

def send_file(filepath, host, port, password):
    key = derive_key(password)
    encrypted_data = encrypt_file(filepath, key)

    with socket.socket() as s:
        s.connect((host, port))
        s.sendall(os.path.basename(filepath).encode() + b'\n')
        s.sendall(len(encrypted_data).to_bytes(8, 'big'))
        s.sendall(encrypted_data)
        print(f"✅ Encrypted file sent to {host}:{port}")

def receive_file(port, password):
    key = derive_key(password)
    with socket.socket() as s:
        s.bind(('0.0.0.0', port))
        s.listen(1)
        print(f"📥 Waiting for file on port {port}...")
        conn, addr = s.accept()
        with conn:
            print(f"🔗 Connection from {addr}")
            filename = b''
            while not filename.endswith(b'\n'):
                filename += conn.recv(1)
            filename = filename.strip().decode()

            size = int.from_bytes(conn.recv(8), 'big')
            encrypted_data = b''
            while len(encrypted_data) < size:
                encrypted_data += conn.recv(BUFFER_SIZE)

            data = decrypt_data(encrypted_data, key)
            with open(f"received_{filename}", 'wb') as f:
                f.write(data)
            print(f"✅ File received and saved as received_{filename}")

def main():
    parser = argparse.ArgumentParser(description="🔐 Secure File Transfer Tool")
    subparsers = parser.add_subparsers(dest="command")

    send_parser = subparsers.add_parser("send")
    send_parser.add_argument("file", help="Path to file")
    send_parser.add_argument("host", help="Receiver IP")
    send_parser.add_argument("port", type=int)
    send_parser.add_argument("password", help="Password for encryption")

    recv_parser = subparsers.add_parser("receive")
    recv_parser.add_argument("port", type=int)
    recv_parser.add_argument("password", help="Password for decryption")

    args = parser.parse_args()

    if args.command == "send":
        send_file(args.file, args.host, args.port, args.password)
    elif args.command == "receive":
        receive_file(args.port, args.password)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

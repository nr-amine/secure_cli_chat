import socket
import threading
import base64
import os
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from protocol import send_frame, recv_frame

pub_keys_d = {}

def listener(client_socket: socket.socket, private_key):
    while True:
        try:
            frame = recv_frame(client_socket)
            if frame is None:
                print("\n[!] Disconnected from server.")
                break

            msg_type = frame.get("type")

            if msg_type == "info":
                print(f"[Server] {frame.get('message')}")
                continue

            if msg_type == "error":
                print(f"[Error] {frame.get('message')}")
                continue

            if msg_type == "key":
                target_user = frame.get("target")
                target_key_pem = frame.get("pubkey")
                try:
                    m_key = serialization.load_pem_public_key(target_key_pem.encode('utf-8'))
                    pub_keys_d[target_user] = m_key
                    print(f"[+] Public key cached for user '{target_user}'")
                except Exception as e:
                    print(f"[!] Failed to parse public key for '{target_user}': {e}")
                continue

            if msg_type == "msg":
                sender = frame.get("sender")
                payload_b64 = frame.get("payload")
                try:
                    full_encrypted_blob = base64.b64decode(payload_b64)
                    if len(full_encrypted_blob) < 256 + 12 + 16:
                        print(f"[!] Received malformed encrypted payload from '{sender}'")
                        continue

                    encrypted_aes_key = full_encrypted_blob[:256]
                    nonce = full_encrypted_blob[256:256 + 12]
                    encrypted_msg = full_encrypted_blob[256 + 12:]

                    aes_key = private_key.decrypt(
                        encrypted_aes_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    aesgcm = AESGCM(aes_key)
                    decrypted_msg = aesgcm.decrypt(nonce, encrypted_msg, None)
                    print(f"\n[DM from {sender}] {decrypted_msg.decode('utf-8')}")
                except Exception as e:
                    print(f"\n[!] Decryption failed for message from '{sender}': {e}")
                continue

            if msg_type == "broadcast":
                sender = frame.get("sender")
                text = frame.get("text")
                print(f"\n[{sender} (Public)] {text}")
                continue

            if msg_type == "users":
                users = frame.get("users", [])
                print("\nConnected users:")
                for usr in users:
                    print(f"  - {usr}")
                continue

        except (ConnectionResetError, BrokenPipeError):
            print("\n[!] Connection lost.")
            break
        except Exception as e:
            print(f"\n[!] Listener error: {e}")
            break

def start_client(host='127.0.0.1', port=1234):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
    except Exception as e:
        print(f"Could not connect to {host}:{port}: {e}")
        return

    print("=== Secure CLI Chat ===")
    username = input("Choose your username: ").strip()
    while not username:
        username = input("Username cannot be empty: ").strip()

    print("[*] Generating ephemeral 2048-bit RSA key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    ser_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Register with server
    send_frame(client_socket, {
        "type": "register",
        "username": username,
        "pubkey": ser_key
    })

    thr = threading.Thread(target=listener, args=(client_socket, private_key), daemon=True)
    thr.start()

    print("\nCommands:")
    print("  /users                 - List online users")
    print("  /getkey <user>         - Fetch and cache public key for user")
    print("  /msg <user> <message>  - Send end-to-end encrypted direct message")
    print("  <message>              - Broadcast cleartext message to all users")
    print("  exit                   - Disconnect and exit\n")

    while True:
        try:
            line = input()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            break

        line_str = line.strip()
        if not line_str:
            continue

        if line_str.lower() == "exit":
            print("Exiting...")
            break

        if line_str == "/users":
            send_frame(client_socket, {"type": "list_users"})
            continue

        if line_str.startswith("/getkey"):
            parts = line_str.split(None, 1)
            if len(parts) < 2:
                print("Usage: /getkey <username>")
                continue
            send_frame(client_socket, {"type": "getkey", "target": parts[1].strip()})
            continue

        if line_str.startswith("/msg"):
            parts = line_str.split(None, 2)
            if len(parts) < 3:
                print("Usage: /msg <username> <message>")
                continue
            target_user = parts[1].strip()
            secret_message = parts[2]

            if target_user not in pub_keys_d:
                print(f"[!] Public key for '{target_user}' not found in cache. Run: /getkey {target_user}")
                continue

            target_pub_key = pub_keys_d[target_user]

            # Generate ephemeral AES-128-GCM session key and 96-bit nonce
            aes_key = AESGCM.generate_key(bit_length=128)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)

            encrypted_msg = aesgcm.encrypt(nonce, secret_message.encode('utf-8'), None)

            # Encrypt AES session key with recipient's RSA-2048 public key via OAEP
            encrypted_aes_key = target_pub_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            full_encrypted_blob = encrypted_aes_key + nonce + encrypted_msg
            payload_b64 = base64.b64encode(full_encrypted_blob).decode('ascii')

            send_frame(client_socket, {
                "type": "msg",
                "target": target_user,
                "payload": payload_b64
            })
            print(f"[Sent DM to {target_user}]: {secret_message}")
            continue

        # Default: cleartext broadcast
        send_frame(client_socket, {
            "type": "broadcast",
            "text": line_str
        })

    client_socket.close()

if __name__ == "__main__":
    start_client()


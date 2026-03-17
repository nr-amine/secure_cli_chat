import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

pub_keys_d = {}

def listener(client_socket, private_key):
    while True:
        try:
            msg = client_socket.recv(4096)
            if msg.startswith(b"KEY//"):
                parts = msg.split(b"//", 2)
                target_user = parts[1].decode('utf-8')
                target_key = parts[2]
                m_key = serialization.load_pem_public_key(target_key)
                pub_keys_d[target_user] = m_key
                print(f"Public key received for {target_user})")
                continue

            if msg.startswith(b"MSG//"):
                parts = msg.split(b"//", 2)
                full_encrypted_blob = parts[2]
                
                encrypted_aes_key = full_encrypted_blob[:256]
                nonce = full_encrypted_blob[256:256+12]
                encrypted_msg = full_encrypted_blob[256+12:]

                aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                 algorithm=hashes.SHA256(),
                                 label=None)
                )
                
                aesgcm = AESGCM(aes_key)
                decrypted_msg = aesgcm.decrypt(nonce, encrypted_msg, None)
                print(f"Decrypted message from {parts[1].decode('utf-8')}: {decrypted_msg.decode('utf-8')}")
                continue

            if msg.startswith(b"USERS//"):
                user_list = msg.decode('utf-8').split("//", 1)[1]
                print("Connected users:")
                for usr in user_list.split(","):
                    print(f"- {usr}")
                continue

            if not msg:
                print("Message is empty, exiting...")
                break
            print(msg.decode('utf-8'))
        except Exception as e:
            print("ERROR: Server CTRL-C'ed or undefined behaviour, exiting...")
            break

def start_client():
    host = '127.0.0.1'
    port = 1234
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print("Choose you username: ", end="")
    username = input()

    ###### RSA Key Generation ######

    print("Generating RSA keys...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    ser_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    ############################

    handshake_bytes = b"EXCHANGE//" + username.encode('utf-8') + b"//" + ser_key
    print("Sending handshake to server...")
    client_socket.send(handshake_bytes)

    thr = threading.Thread(target=listener, args=(client_socket, private_key))
    thr.start()
    while True:
        msg = input()

        if msg.startswith("/getkey"):
            _, target_user = msg.split()
            client_socket.send(f"GETKEY//{target_user}".encode('utf-8'))
            continue

        if msg.startswith("/msg"):
            _, target_user, message = msg.split(" ", 2)
            if target_user not in pub_keys_d:
                print(f"Public key for {target_user} not found. Use /getkey to retrieve it.")
                continue
            target_pub_key = pub_keys_d[target_user]

            aes_key = AESGCM.generate_key(bit_length=128)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)

            encrypted_msg = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
            
            encrypted_aes_key = target_pub_key.encrypt(
                aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None)
            )
            
            full_encrypted_pk = encrypted_aes_key + nonce + encrypted_msg
            
            targeted_msg = b"MSG//" + target_user.encode('utf-8') + b"//" + full_encrypted_pk
            client_socket.send(targeted_msg)
            continue

        if msg.startswith("/users"):
            client_socket.send(b"//USERS")
            continue

        if msg.lower() == "exit":
            print("Exiting...")
            break
        full_msg = f"{username}: {msg}"
        client_socket.send(full_msg.encode('utf-8'))
    client_socket.close()

if __name__ == "__main__":
    start_client()

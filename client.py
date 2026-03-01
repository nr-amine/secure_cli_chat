import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def listner(client_socket):
    while True:
        try:
            msg = client_socket.recv(1024)
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
    print("Generating RSA keys...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    ser_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
    handshake_msg = f"EXCHANGE//{username}//{ser_key}//"
    print(f"Connected to server at {host}:{port}")
    client_socket.send(handshake_msg.encode('utf-8'))

    thr = threading.Thread(target=listner, args=(client_socket,))
    thr.start()
    while True:
        msg = input()
        if msg.lower() == "exit":
            print("Exiting...")
            break
        full_msg = f"{username}: {msg}"
        client_socket.send(full_msg.encode('utf-8'))
    client_socket.close()

if __name__ == "__main__":
    start_client()

import unittest
import socket
import threading
import time
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from protocol import send_frame, recv_frame
import server

class TestSecureChatE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start server on a high random test port
        cls.port = 14567
        cls.server_thread = threading.Thread(target=server.start_server, args=('127.0.0.1', cls.port), daemon=True)
        cls.server_thread.start()
        time.sleep(0.2)

    def test_e2e_hybrid_encryption(self):
        # Setup Alice
        alice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        alice_sock.connect(('127.0.0.1', self.port))
        alice_priv = rsa.generate_private_key(65537, 2048)
        alice_pub_pem = alice_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        send_frame(alice_sock, {"type": "register", "username": "Alice", "pubkey": alice_pub_pem})
        resp = recv_frame(alice_sock)
        self.assertEqual(resp.get("type"), "info")

        # Setup Bob
        bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bob_sock.connect(('127.0.0.1', self.port))
        bob_priv = rsa.generate_private_key(65537, 2048)
        bob_pub_pem = bob_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        send_frame(bob_sock, {"type": "register", "username": "Bob", "pubkey": bob_pub_pem})
        resp = recv_frame(bob_sock)
        self.assertEqual(resp.get("type"), "info")

        # Alice requests Bob's public key
        send_frame(alice_sock, {"type": "getkey", "target": "Bob"})
        key_resp = recv_frame(alice_sock)
        self.assertEqual(key_resp.get("type"), "key")
        self.assertEqual(key_resp.get("target"), "Bob")
        bob_cached_pub = serialization.load_pem_public_key(key_resp["pubkey"].encode('utf-8'))

        # Alice encrypts message for Bob using Hybrid RSA-OAEP + AES-128-GCM
        secret_plaintext = "Sensitive medical credentials 12345"
        aes_key = AESGCM.generate_key(bit_length=128)
        nonce = os.urandom(12)
        encrypted_msg = AESGCM(aes_key).encrypt(nonce, secret_plaintext.encode('utf-8'), None)
        encrypted_aes_key = bob_cached_pub.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        full_blob = encrypted_aes_key + nonce + encrypted_msg
        payload_b64 = base64.b64encode(full_blob).decode('ascii')

        # Alice transmits encrypted message to Bob via server
        send_frame(alice_sock, {"type": "msg", "target": "Bob", "payload": payload_b64})

        # Bob receives message frame
        bob_received_frame = recv_frame(bob_sock)
        self.assertEqual(bob_received_frame.get("type"), "msg")
        self.assertEqual(bob_received_frame.get("sender"), "Alice")

        # Bob decrypts payload
        received_blob = base64.b64decode(bob_received_frame["payload"])
        rec_enc_aes_key = received_blob[:256]
        rec_nonce = received_blob[256:268]
        rec_ciphertext = received_blob[268:]

        recovered_aes_key = bob_priv.decrypt(
            rec_enc_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.assertEqual(recovered_aes_key, aes_key)

        decrypted_text = AESGCM(recovered_aes_key).decrypt(rec_nonce, rec_ciphertext, None).decode('utf-8')
        self.assertEqual(decrypted_text, secret_plaintext)

        # Test Broadcast
        send_frame(alice_sock, {"type": "broadcast", "text": "Public Announcement"})
        bcast_frame = recv_frame(bob_sock)
        self.assertEqual(bcast_frame.get("type"), "broadcast")
        self.assertEqual(bcast_frame.get("sender"), "Alice")
        self.assertEqual(bcast_frame.get("text"), "Public Announcement")

        alice_sock.close()
        bob_sock.close()

if __name__ == "__main__":
    unittest.main()

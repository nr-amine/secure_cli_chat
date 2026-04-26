# secure-cli-chat (wip)

making a secure terminal messaging app from scratch. Mainly to move away from basic scripts to applied crypto. 

right now it just handles the networking and rsa key distribution. the actual message encryption is the next step.

### what it does so far
- multi-threaded python sockets so multiple clients can connect at once.
- generates a 2048-bit RSA key pair locally when you start the client.
- server acts as a dumb directory. it just holds the public keys and routes traffic.
- uses a custom byte-level protocol with `//` delimiters so the PEM formatting doesn't get corrupted over the socket.

### how to run it
you just need python and the cryptography library.

    pip install cryptography

start the server first:
   
    python server.py

open another terminal and run the client:

    python client.py

4. pick a username. it will freeze for a second to generate your keys, then send your public key to the server.
5. type `/getkey [username]` to fetch someone else's public key from the server directory.

### to-do 
- [x] basic multi-threaded socket chat
- [x] rsa key generation and server-side directory
- [x] actually use the keys to encrypt the messages (hybrid encryption with aes)
- [ ] forward secrecy (Diffie hellman?)

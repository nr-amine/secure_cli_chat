import socket
import threading

users_d = {}


def handler(con, addr):
    print(f"Connection established at {addr}")

    while True:
        try:
            msg = con.recv(2048)
            if not msg:
                print("Empty message, exiting...")
                break
            if msg.startswith(b"EXCHANGE//"):
                _, username, ser_key, _ = msg.decode('utf-8').split("//")
                users_d[con] = (username, ser_key)
                print(f"User {username} has joined the chat.")
                print(f"Directory saved for {username} with public key.")
                continue
            if msg.startswith(b"GETKEY//"):
                _, target_user = msg.decode('utf-8').split("//")
                found = False
                for usr_con, (usr_name, usr_key) in users_d.items():
                    if usr_name == target_user:
                        con.send(f"KEY//{target_user}//{usr_key}".encode('utf-8'))
                        found = True
                        break
                if not found:
                    con.send(f"ERROR//User {target_user} not found.".encode('utf-8'))
                continue
            print(msg.decode('utf-8'))
            for usr in users_d:
                if usr != con:
                    usr.send(msg)
        except Exception as e:
            print(f"ERROR: client CTRL-C'ed or undefined behaviour, exiting...")
            break

    print(f"{addr} : DISCONNECTED")
    del users_d[con]
    con.close()


def start_server():
    host = '127.0.0.1'
    port = 1234
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    print(f"Server Listening on {host}:{port}")
    server_socket.listen()

    while True:
        conn, address = server_socket.accept()
        users_d[conn] = None
        thr = threading.Thread(target=handler, args=(conn, address))
        thr.start()

        print(f"Active connections: {threading.active_count()-1}")



if __name__ == "__main__":
    start_server()
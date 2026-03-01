import socket
import threading

users = []


def handler(con, addr):
    print(f"Connection established at {addr}")

    while True:
        try:
            msg = con.recv(1024)
            if not msg:
                print("Empty message, exiting...")
                break
            print(msg.decode('utf-8'))
            for usr in users:
                if usr != con:
                    usr.send(msg)
        except Exception as e:
            print(f"ERROR: client CTRL-C'ed or undefined behaviour, exiting...")
            break

    print(f"{addr} : DISCONNECTED")
    users.remove(con)
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
        users.append(conn)
        thr = threading.Thread(target=handler, args=(conn, address))
        thr.start()

        print(f"Active connections: {threading.active_count()-1}")



if __name__ == "__main__":
    start_server()
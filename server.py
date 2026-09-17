import socket
import threading
from protocol import send_frame, recv_frame

users_d = {}
users_lock = threading.Lock()

def deliver_connected_users():
    with users_lock:
        return [usr_info[0] for usr_info in users_d.values() if usr_info is not None]

def handler(con: socket.socket, addr):
    print(f"Connection established from {addr}")

    while True:
        try:
            frame = recv_frame(con)
            if frame is None:
                break

            msg_type = frame.get("type")

            if msg_type == "register":
                username = frame.get("username", "").strip()
                pubkey = frame.get("pubkey", "")
                if not username:
                    send_frame(con, {"type": "error", "message": "Username cannot be empty."})
                    continue

                with users_lock:
                    if any(info and info[0] == username for c, info in users_d.items() if c != con):
                        send_frame(con, {"type": "error", "message": f"Username '{username}' is already taken."})
                        continue
                    users_d[con] = (username, pubkey)

                print(f"User '{username}' registered public key from {addr}")
                send_frame(con, {"type": "info", "message": f"Welcome, {username}!"})
                continue

            if msg_type == "getkey":
                target_user = frame.get("target")
                found_key = None
                with users_lock:
                    for usr_con, usr_info in users_d.items():
                        if usr_info is not None and usr_info[0] == target_user:
                            found_key = usr_info[1]
                            break

                if found_key:
                    send_frame(con, {"type": "key", "target": target_user, "pubkey": found_key})
                else:
                    send_frame(con, {"type": "error", "message": f"User '{target_user}' not found."})
                continue

            if msg_type == "list_users":
                user_list = deliver_connected_users()
                send_frame(con, {"type": "users", "users": user_list})
                continue

            if msg_type == "msg":
                target_user = frame.get("target")
                payload = frame.get("payload")

                sender_user = "Anonymous"
                target_con = None
                with users_lock:
                    if con in users_d and users_d[con]:
                        sender_user = users_d[con][0]
                    for usr_con, usr_info in users_d.items():
                        if usr_info is not None and usr_info[0] == target_user:
                            target_con = usr_con
                            break

                if target_con is not None:
                    send_frame(target_con, {
                        "type": "msg",
                        "sender": sender_user,
                        "payload": payload
                    })
                else:
                    send_frame(con, {"type": "error", "message": f"User '{target_user}' is not online."})
                continue

            if msg_type == "broadcast":
                text = frame.get("text", "")
                with users_lock:
                    sender_user = users_d.get(con, ("Anonymous",))[0]
                    recipients = [c for c in users_d.keys() if c != con]

                for recipient in recipients:
                    try:
                        send_frame(recipient, {
                            "type": "broadcast",
                            "sender": sender_user,
                            "text": text
                        })
                    except Exception:
                        pass
                continue

        except (ConnectionResetError, BrokenPipeError):
            break
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
            break

    with users_lock:
        user_info = users_d.pop(con, None)
    try:
        con.close()
    except Exception:
        pass

    username = user_info[0] if user_info else str(addr)
    print(f"User '{username}' disconnected.")

def start_server(host='127.0.0.1', port=1234):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"Server listening on {host}:{port}")

    while True:
        try:
            conn, address = server_socket.accept()
            with users_lock:
                users_d[conn] = None
            thr = threading.Thread(target=handler, args=(conn, address), daemon=True)
            thr.start()
            with users_lock:
                count = len(users_d)
            print(f"Active connections: {count}")
        except KeyboardInterrupt:
            print("\nServer shutting down...")
            break

    server_socket.close()

if __name__ == "__main__":
    start_server()
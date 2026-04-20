import os
import socket
import threading

import paramiko

from app.database import SessionLocal
from app.models import CommandLog, SessionAttack
from app.services.scoring import compute_score, sanitize_password

KEY_FILE = "server.key"

if not os.path.exists(KEY_FILE):
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(KEY_FILE)

HOST_KEY = paramiko.RSAKey(filename=KEY_FILE)


class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.username = None
        self.password = None

    def check_auth_password(self, username, password):
        print(f"[LOGIN] {self.client_ip} -> {username}:{password}")
        self.username = username
        self.password = sanitize_password(password)
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def save_session(ip, username, password, commands):
    db = SessionLocal()
    try:
        score = compute_score(username, password, commands)

        session = SessionAttack(
            ip_source=ip,
            username=username,
            password=password,
            success=True,
            threat_score=score
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        for cmd in commands:
            log = CommandLog(
                session_id=session.id,
                command=cmd
            )
            db.add(log)

        db.commit()
        print(f"[DB] Session sauvegardée : id={session.id}, ip={ip}, score={score}")
    except Exception as exc:
        db.rollback()
        print(f"[ERREUR DB] {exc}")
    finally:
        db.close()


def fake_command_output(command: str) -> bytes:
    cmd = command.strip()

    if cmd == "ls":
        return b"bin  boot  dev  etc  home  root  tmp  usr  var\n"

    if cmd == "pwd":
        return b"/root\n"

    if cmd == "whoami":
        return b"root\n"

    if cmd == "uname -a":
        return b"Linux ubuntu 5.15.0-91-generic x86_64 GNU/Linux\n"

    if cmd == "id":
        return b"uid=0(root) gid=0(root) groups=0(root)\n"

    if cmd == "ps":
        return b"  PID TTY          TIME CMD\n 1023 pts/0    00:00:00 bash\n 1054 pts/0    00:00:00 ps\n"

    if cmd == "cat /etc/passwd":
        return b"root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash\n"

    if cmd.startswith("cd "):
        return b""

    if cmd.startswith("curl "):
        return b"HTTP/1.1 200 OK\nContent-Length: 245\n\n<html><body>OK</body></html>\n"

    if cmd.startswith("wget "):
        return (
            b"--2026-04-20--  http://test.com\n"
            b"Resolving test.com... 93.184.216.34\n"
            b"Connecting to test.com|93.184.216.34|:80... connected.\n"
            b"HTTP request sent, awaiting response... 200 OK\n"
            b"Saving to: 'index.html'\n"
        )

    if cmd.startswith("chmod "):
        return b""

    if cmd.startswith("bash"):
        return b""

    if cmd == "exit":
        return b"logout\n"

    return b"command not found\n"


def handle_connection(client, addr):
    ip = addr[0]
    print(f"[+] Nouvelle connexion : {ip}")

    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)

    server = SSHServer(ip)

    try:
        transport.start_server(server=server)
    except paramiko.SSHException as exc:
        print(f"[ERREUR SSH] {ip} -> {exc}")
        transport.close()
        return

    chan = transport.accept(20)
    if chan is None:
        print(f"[INFO] Aucun canal ouvert pour {ip}")
        transport.close()
        return

    print(f"[SESSION] Ouverte avec {ip}")
    commands = []

    try:
        chan.send(b"Welcome to Ubuntu 20.04 LTS\n")
        chan.send(b"$ ")

        while True:
            command = ""
            while not command.endswith("\r"):
                data = chan.recv(1024)
                if not data:
                    break

                decoded = data.decode("utf-8", errors="ignore")
                command += decoded

                if "\r" in decoded or "\n" in decoded:
                    break

            command = command.strip()

            if not command:
                chan.send(b"$ ")
                continue

            print(f"[CMD] {ip} -> {command}")
            commands.append(command)

            output = fake_command_output(command)
            chan.send(output)

            if command == "exit":
                break

            chan.send(b"$ ")

    except Exception as exc:
        print(f"[ERREUR SESSION] {ip} -> {exc}")

    finally:
        save_session(ip, server.username, server.password, commands)
        try:
            chan.close()
        except Exception:
            pass
        try:
            transport.close()
        except Exception:
            pass
        print(f"[SESSION FERMEE] {ip}")


def start_server(host="0.0.0.0", port=2222):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)

    print(f"[HONEYPOT] SSH actif sur {host}:{port}")

    while True:
        client, addr = sock.accept()
        thread = threading.Thread(target=handle_connection, args=(client, addr), daemon=True)
        thread.start()


if __name__ == "__main__":
    start_server()
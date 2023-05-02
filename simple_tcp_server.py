import socket
import threading
import sys

class SimpleTcpServer:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"[*] Listening on {self.host}:{self.port}")

        while True:
            client, address = server.accept()
            print(f"[*] Accepted connection from {address[0]}:{address[1]}")
            client_handler = threading.Thread(target=self.handle_client, args=(client,))
            client_handler.start()

    def handle_client(self, client_socket):
        with client_socket:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                print(f"Received data: {data.decode('utf-8')}")
                client_socket.sendall(data)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python simple_tcp_server.py <host> <port>")
        sys.exit(1)

    host, port = sys.argv[1], int(sys.argv[2])
    server = SimpleTcpServer(host, port)
    server.start()

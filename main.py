import subprocess
import socket
import threading


class TCPIPServer:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.running = False
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.settimeout(1)  # Set a timeout of 1 second

    def start(self):
        self.running = True
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(5)
    
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                client_socket.close()
            except socket.timeout:
                pass

    def stop(self):
        self.running = False
        self.server_socket.close()

class TCPIPTools:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.server = TCPIPServer(server_ip, server_port)

    def start_server(self):
        server_thread = threading.Thread(target=self.server.start)
        server_thread.start()

    def stop_server(self):
        self.server.stop()

    def run_command(self, command, title, ignore_errors=False):
        print(f"\n=== {title} ===")
        try:
            subprocess.run(command, text=True, check=True)
        except subprocess.CalledProcessError as e:
            if not ignore_errors:
                print(f"Error: {e}")

    def netstat(self):
        self.run_command(["netstat", "-a"], "Netstat")

    def ping(self, count=4):
        self.run_command(["ping", "-c", str(count), self.server_ip], "Ping")

    def traceroute(self):
        self.run_command(["traceroute", self.server_ip], "Traceroute")

    def nmap(self):
        self.run_command(["nmap", "-p", f"{self.server_port}", self.server_ip], "Nmap")

    def tcpdump(self, count=10):
        self.run_command(["sudo", "tcpdump", "-i", "lo", "-c", str(count), f"port {self.server_port}"], "Tcpdump")

    def nslookup(self):
        self.run_command(["nslookup", self.server_ip], "Nslookup")

    def ip(self):
        # "ip" is not on macOS, so use "ifconfig" instead
        self.run_command(["ifconfig"], "Ip")

    def telnet(self):
        self.run_command(["telnet", self.server_ip, str(self.server_port)], "Telnet", ignore_errors=True)

if __name__ == "__main__":
    SERVER_IP = "127.0.0.1"
    SERVER_PORT = 12345

    tools = TCPIPTools(SERVER_IP, SERVER_PORT)
    tools.start_server()

    tools.netstat()
    tools.ping()
    tools.traceroute()
    tools.nmap()
    tools.tcpdump()
    tools.nslookup()
    tools.ip()
    tools.telnet()

    tools.stop_server()
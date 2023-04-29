import subprocess
import time
import socket

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

class NetworkTool:
    def __init__(self, target):
        self.target = target

    def run(self, command):
        """Run a command in a subprocess and return its output."""
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            if error:
                print(f"Error running {' '.join(command)}: {error}")
            return output.decode('utf-8')
        except Exception as e:
            print(f"Exception encountered: {str(e)}")
            return None

class IPDNSDetailTool(NetworkTool):
    def execute(self):
        """Get IP and DNS details."""
        try:
            IP = socket.gethostbyname(self.target)
            host = socket.getfqdn(self.target)
            return f'IP: {IP}, Host: {host}'
        except Exception as e:
            return f"Exception encountered: {str(e)}"

    def reverse_lookup(self):
        """Perform a reverse DNS lookup on the target IP."""
        try:
            name, alias, addresslist = socket.gethostbyaddr(self.target)
            return f'Name: {name}, Alias: {alias}, Address list: {addresslist}'
        except Exception as e:
            return f"Exception encountered: {str(e)}"

class PingTool(NetworkTool):
    def execute(self, count='4'):
        """Ping the target."""
        command = ['ping', '-c', count, self.target]
        return self.run(command)

    def flood_ping(self):
        """Flood ping the target."""
        command = ['ping', '-f', self.target]
        return self.run(command)

class NsLookupTool(NetworkTool):
    def execute(self, record_type='A'):
        """Perform an NS lookup on the target."""
        command = ['nslookup', '-query=' + record_type, self.target]
        return self.run(command)

    def reverse_nslookup(self):
        """Perform a reverse NS lookup on the target."""
        command = ['nslookup', self.target]
        return self.run(command)

class TracerouteTool(NetworkTool):
    def execute(self, max_hops='30'):
        """Perform a traceroute on the target."""
        command = ['traceroute', '-m', max_hops, self.target]
        return self.run(command)

    def execute_asn(self):
        """Perform a traceroute with ASN lookup on the target."""
        command = ['traceroute', '-A', self.target]
        return self.run(command)

class NetcatTool(NetworkTool):
    def execute(self, ports, timeout='2'):
        """Perform a netcat on the target."""
        results = []
        for port in ports:
            command = ['nc', '-vz', '-w', timeout, self.target, str(port)]
            results.append(self.run(command))
        return results

    def listen(self, port):
        """Listen on a specific port."""
        command = ['nc', '-l', '-p', str(port)]
        return self.run(command)

    def scan_ports_range(self, start_port, end_port, timeout='2'):
        """Perform a netcat on the target for a range of ports."""
        results = []
        for port in range(start_port, end_port + 1):
            command = ['nc', '-vz', '-w', timeout, self.target, str(port)]
            results.append(self.run(command))
        return results

class IPerfTool(NetworkTool):
    def execute(self, duration='10'):
        """Perform an iPerf on the target."""
        command = ['iperf3', '-c', self.target, '-t', duration, '-i', '2', '--get-server-output']
        return self.run(command)

    def reverse_execute(self, duration='10'):
        """Perform an iPerf on the target in reverse mode."""
        command = ['iperf3', '-c', self.target, '-R', '-t', duration, '-i', '2', '--get-server-output']
        return self.run(command)

class TcpdumpTool(NetworkTool):
    def execute(self, duration='10'):
        """Perform a tcpdump on the target."""
        command = ['timeout', duration, 'tcpdump', '-i', 'any', '-c', '10', '-n']
        return self.run(command)

    def execute_extended(self, duration='10'):
        """Perform a tcpdump on the target with extended information."""
        command = ['timeout', duration, 'tcpdump', '-i', 'any', '-c', '10', '-n', '-v']
        return self.run(command)

class TSharkTool(NetworkTool):
    def execute(self, duration='10', filter_expression=""):
        """Perform a tshark on the target."""
        command = ['timeout', duration, 'tshark', '-i', 'any', '-c', '10', '-n']
        if filter_expression:
            command.extend(['-Y', filter_expression])
        return self.run(command)

    def execute_http(self, duration='10'):
        """Perform a tshark on the target with HTTP filter."""
        command = ['timeout', duration, 'tshark', '-i', 'any', '-c', '10', '-n', '-Y', 'http']
        return self.run(command)

class NetcatConnectionTool(NetworkTool):
    def execute(self, port, message):
        """Establish a connection to a remote server and send a message."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.target, port))
            s.sendall(bytes(message, 'utf-8'))
            data = s.recv(1024)
        return 'Received', repr(data)

class SimpleTcpClient(NetworkTool):
    def execute(self, port, message):
        """Establish a TCP connection to a server and send a message."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.target, port))
            s.sendall(bytes(message, 'utf-8'))
            data = s.recv(1024)
        return 'Received', repr(data)

class SimpleTcpServer(NetworkTool):
    def execute(self, port):
        """Create a simple TCP server that listens for incoming connections."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.target, port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    conn.sendall(data)

class TCPConnection(NetworkTool):
    def __init__(self, target, port):
        super().__init__(target)
        self.port = port

    def execute(self, message):
        """Establish a TCP connection to the target and send a message."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.target, self.port))
            s.sendall(bytes(message, 'utf-8'))
            data = s.recv(1024)
        return 'Received', repr(data)

class UDPConnection(NetworkTool):
    def __init__(self, target, port):
        super().__init__(target)
        self.port = port

    def execute(self, message):
        """Establish a UDP connection to the target and send a message."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(bytes(message, 'utf-8'), (self.target, self.port))
            data, addr = s.recvfrom(1024)
        return 'Received', repr(data)

class HTTPRequestTool(NetworkTool):
    def execute(self):
        """Make an HTTP request to the target and handle retries."""
        session = requests.Session()
        retry = Retry(total=5, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        try:
            response = session.get('http://' + self.target)
            response.raise_for_status()
            return response.text
        except requests.exceptions.HTTPError as errh:
            return f"HTTP Error: {errh}"
        except requests.exceptions.ConnectionError as errc:
            return f"Error Connecting: {errc}"
        except requests.exceptions.Timeout as errt:
            return f"Timeout Error: {errt}"
        except requests.exceptions.RequestException as err:
            return f"Oops: Something Else {err}"

class NetworkAnalyzer:
    def __init__(self, target):
        self.target = target
        self.tools = [IPDNSDetailTool(target), PingTool(target), NsLookupTool(target), TracerouteTool(target),
                      NetcatTool(target), IPerfTool(target), TcpdumpTool(target), TSharkTool(target),
                      NetcatConnectionTool(target), SimpleTcpClient(target),
                      SimpleTcpServer(target), TCPConnection(target, 80), UDPConnection(target, 53), 
                      HTTPRequestTool(target)]

    def run_analysis(self):
        """Run an analysis using all tools."""
        for tool in self.tools:
            if isinstance(tool, NetcatTool):
                # Scan a range of ports
                start_port = 20
                end_port = 25
                results = tool.scan_ports_range(start_port, end_port)
                for port, output in zip(range(start_port, end_port + 1), results):
                    print(f"{type(tool).__name__} (Port: {port}) Output:\n{output}")
            elif isinstance(tool, TSharkTool):
                output = tool.execute(filter_expression='tcp')
                print(f"{type(tool).__name__} (Filtered by TCP) Output:\n{output}")
            else:
                output = tool.execute()
                print(f"{type(tool).__name__} Output:\n{output}")
            time.sleep(1)  # Pause between each tool for readability

def main():
    """Main function to run the network analysis."""
    target = "google.com"  # Set your target
    network_analyzer = NetworkAnalyzer(target)
    network_analyzer.run_analysis()

if __name__ == "__main__":
    main()
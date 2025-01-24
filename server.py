import ssl
import sys
import re
import traceback
import time
from socket import *
from rich.live import Live
from rich.table import Table
from rich.console import Console
from urllib.parse import quote
from ipaddress import ip_address, ip_network
import json

#HOST = "127.0.0.1"
HOST = "0.0.0.0"
#HOST = "172.20.10.4" #for other laptop same network (Waleed Network)
PORT = 8800
FILE = "index.html"
certfile = "./ssl/server_cert.pem"
keyfile = "./ssl/server_key.pem"
cafile = "./ssl/ca_cert.pem"
ciphers = None
ssl_version = None
option_test_switch = 1
#request_limits = {"127.0.0.1": (10, 60)} 
request_limits = {"172.20.10.2": (3, 60)} 
request_times = {}
blacklist = set() 
#HONEYPOT_HOST = "127.0.0.1"
HONEYPOT_HOST = "172.20.10.4"
#HONEYPOT_HOST = "39.37.210.155"
HONEYPOT_PORT = 8801
PASSWORD_STORE = {"client1": "123"}

log_file = "server_logs.json"

# TLS version dictionary
version_dict = {
    "tlsv1.0": ssl.PROTOCOL_TLSv1,
    "tlsv1.1": ssl.PROTOCOL_TLSv1_1,
    "tlsv1.2": ssl.PROTOCOL_TLSv1_2,
    "sslv23": ssl.PROTOCOL_TLS,
}

# Function to log data
def log_activity(log_entry):
    try:
       
        try:
            with open(log_file, "r") as f:
                content = f.read().strip()
                logs = json.loads(content) if content else []
        except (FileNotFoundError, json.JSONDecodeError):
            logs = []

       
        logs.append(log_entry)

       
        with open(log_file, "w") as f:
            json.dump(logs, f, indent=4)
    except Exception as e:
        print(f"Error logging activity: {e}")

def authenticate_client(password):
    if password in PASSWORD_STORE.values():
        print("Password authenticated successfully.")
        return True
    else:
        print("Password authentication failed!")
        return False

# Rate limiting function
def rate_limit(client_ip):
    limit, period = request_limits.get(client_ip, (None, None))
    if limit is None:
        return True  

    current_time = time.time()
    past_requests = request_times.get(client_ip, [])
    past_requests = [t for t in past_requests if current_time - t < period]
    request_times[client_ip] = past_requests

    if len(past_requests) < limit:
        request_times[client_ip].append(current_time)
        return True
    return False

def check_intrusion(request):
   
    intrusion_patterns = [
        r"DROP TABLE",     # SQL injection
        r"<script.*?>",    # XSS
        r"' OR '1'='1"     # SQL injection bypass
    ]
    for pattern in intrusion_patterns:
        if re.search(pattern, request, re.IGNORECASE):
            return True
    return False

# SSL wrapping function
def ssl_wrap_socket(sock):
    sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sslContext.load_cert_chain(certfile, keyfile)
    sslContext.load_verify_locations(cafile)
    sslContext.verify_mode = ssl.CERT_REQUIRED
    if ciphers:
        sslContext.set_ciphers(ciphers)
    
    wrapped_socket = sslContext.wrap_socket(sock, server_side=True)
    try:
       
        print("TLS Handshake Completed")
        print(f"Cipher: {wrapped_socket.cipher()}")
        print(f"SSL/TLS Version: {wrapped_socket.version()}")
        print(f"Client Certificate: {wrapped_socket.getpeercert(binary_form=False)}")
    except ssl.SSLError as e:
        print("SSL handshake failed:", e)
        print(traceback.format_exc())
    return wrapped_socket
    
# Create dashboard
def create_dashboard(connections):
    table = Table(title="Server Dashboard")
    table.add_column("IP Address", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("TLS Details", justify="left")
    table.add_column("Rate Limited", justify="center")
    table.add_column("City", justify="center")
    table.add_column("Country", justify="center")
    
    for conn in connections:
        table.add_row(
            conn["ip"],
            conn["status"],
            f"{conn['tls_version']} / {conn['cipher']}",
            conn["rate_limited"],
            conn["city"],
            conn["country"],
        )
    
    return table

# Main server loop
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind((HOST, int(PORT)))
serverSocket.listen(10)

connections = []  

with Live(create_dashboard(connections), console=Console(), refresh_per_second=1) as live_dashboard:
    while True:
        print('Ready to serve...')
        newSocket, addr = serverSocket.accept()
        client_ip = addr[0]
        
        # Proceed with TLS wrapping
        connectionSocket = ssl_wrap_socket(newSocket)
        tls_info = connectionSocket.cipher()
        tls_version = connectionSocket.version()

        try:
           
            message = connectionSocket.recv(1024) 
            print("Received message:", message.decode())
            city = "Unknown City"
            country = "Unknown Country"
            password = None

           
            for line in message.decode().split("\r\n"):
                if line.startswith("X-Country:"):
                    country = line.split(":", 1)[1].strip()
                elif line.startswith("X-City:"):
                    city = line.split(":", 1)[1].strip()
                elif line.startswith("X-Password:"):
                    password = line.split(":", 1)[1].strip()
            print(city,country,password)
           
            
            if not authenticate_client(password):
                response = (
                    "HTTP/1.1 401 Unauthorized\r\n"
                    "Content-Type: text/html\r\n\r\n"
                    "<html><body><h1>401 Unauthorized</h1></body></html>"
                )
                connectionSocket.sendall(response.encode())
                connectionSocket.close()
                continue
            
            connections.append({
                "ip": client_ip,
                "status": "Connected",
                "tls_version": tls_version,
                "cipher": tls_info[0],
                "rate_limited": "No",
                "city":city,
                "country":country
            })
            live_dashboard.update(create_dashboard(connections)) 
            
            # Check for intrusion attempts
            if not rate_limit(client_ip):
                print(f"Rate limit exceeded for {client_ip}")
                blacklist.add(client_ip)
                connections.append({"ip": client_ip, "status": "Blocked", "tls_version": "-", "cipher": "-", "rate_limited": "Yes","city":city,"country":country})
                live_dashboard.update(create_dashboard(connections))
                try:
                    response = (
                        "HTTP/1.1 429 Too Many Requests\r\n"
                        "Content-Type: text/html\r\n"
                        "Connection: close\r\n\r\n"
                        "<html><body><h1>429 Too Many Requests</h1>"
                        "<p>You have exceeded the rate limit.</p></body></html>"
                    )
                    connectionSocket.sendall(response.encode())
                except Exception as e:
                    print(f"Error sending rate limit response: {e}")
                finally:
                    log_entry = {
                        "timestamp": time.ctime(),
                        "ip": client_ip,
                        "city": city,
                        "country": country,
                        "tls_version": tls_version,
                        "cipher": tls_info[0],
                        "rate_limited": "Yes",
                        "intrusion_detected": "Yes" if check_intrusion(message.decode()) else "No"
                    }
                    log_activity(log_entry)
                    connectionSocket.shutdown(SHUT_RDWR)
                    connectionSocket.close()
                continue
            if check_intrusion(message.decode()):
                print(f"Intrusion attempt detected from {client_ip}")
                try:
                   
                    request_line = message.decode().split("\r\n")[0]
                    if " " not in request_line or len(request_line.split(" ", 2)) < 2:
                        raise ValueError("Malformed HTTP request line")

                   
                    path_with_query = request_line.split(" ", 2)[1] 


                   
                    response = (
                        "HTTP/1.1 302 Found\r\n"
                        f"Location: https://{HONEYPOT_HOST}:{HONEYPOT_PORT}{path_with_query}\r\n"
                        "Content-Type: text/html\r\n\r\n"
                        "<html><body><h1>You are being redirected...</h1></body></html>"
                    )
                    print(f"Redirecting to Honeypot: {HONEYPOT_HOST}:{HONEYPOT_PORT}{path_with_query}")
                    connectionSocket.sendall(response.encode())

                except (IndexError, ValueError) as e:
                   
                    print(f"Error parsing request line: {e}")
                    connectionSocket.sendall(
                        b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n"
                        b"<html><body><h1>400 Bad Request</h1></body></html>"
                    )
                except Exception as e:
                    
                    print(f"Unexpected error during redirection: {e}")
                finally:
                    log_entry = {
                        "timestamp": time.ctime(),
                        "ip": client_ip,
                        "city": city,
                        "country": country,
                        "tls_version": tls_version,
                        "cipher": tls_info[0],
                        "rate_limited": "No",
                        "intrusion_detected": "Yes"
                    }
                    log_activity(log_entry)
                    connectionSocket.shutdown(SHUT_RDWR)
                    connectionSocket.close()
                continue

            log_entry = {
                "timestamp": time.ctime(),
                "ip": client_ip,
                "city": city,
                "country": country,
                "tls_version": tls_version,
                "cipher": tls_info[0],
                "rate_limited": "No",
                "intrusion_detected":"No"
            }
            log_activity(log_entry)
           
            filename = message.split()[1].decode("utf-8")
            print("Requested file:", filename)

           
            with open(filename[1:], "r") as f:
                outputdata = f.read()

            response_headers = {
                'Content-Type': 'text/html; encoding=utf8',
                'Content-Length': len(outputdata),
                'Connection': 'close',
            }
            response_headers_raw = ''.join(f'{k}: {v}\r\n' for k, v in response_headers.items())
            connectionSocket.send('HTTP/1.1 200 OK\r\n'.encode())
            connectionSocket.send(response_headers_raw.encode())
            connectionSocket.send(b'\r\n')
            connectionSocket.send(outputdata.encode())
            connectionSocket.shutdown(SHUT_RDWR)
            print(f"Response sent to {client_ip}")

        except IOError:
           
            connectionSocket.send(b"HTTP/1.1 404 Not Found\r\n")
            connectionSocket.send(b'Content-Type: text/html\r\n\r\n')
            connectionSocket.send(b'<html><body><h1>404 Not Found</h1></body></html>')
            connectionSocket.shutdown(SHUT_RDWR)
            print(f"File not found: {filename}")
        finally:
            connectionSocket.close()

serverSocket.close()
sys.exit(0)

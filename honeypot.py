import ssl
from socket import *
import time

#HONEYPOT_HOST = "127.0.0.1"
HONEYPOT_HOST = "0.0.0.0"
HONEYPOT_PORT = 8801
certfile = "./ssl/server_cert.pem"
keyfile = "./ssl/server_key.pem"
cafile = "./ssl/ca_cert.pem"

# SSL wrapping function for Honeypot server
def ssl_wrap_socket(sock):
    sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sslContext.load_cert_chain(certfile, keyfile)
    sslContext.load_verify_locations(cafile)
    sslContext.verify_mode = ssl.CERT_NONE  
    return sslContext.wrap_socket(sock, server_side=True)

# Start the honeypot server
honeypotSocket = socket(AF_INET, SOCK_STREAM)
honeypotSocket.bind((HONEYPOT_HOST, HONEYPOT_PORT))
honeypotSocket.listen(10)

print(f"Honeypot server running on {HONEYPOT_HOST}:{HONEYPOT_PORT}...")

while True:
    conn, addr = honeypotSocket.accept()
    client_ip = addr[0]
    print(f"[*] Connection from {client_ip}")

   
    ssl_conn = ssl_wrap_socket(conn)

    try:
       
        message = ssl_conn.recv(1024).decode() 
        print(f"[Honeypot] Received from {client_ip}: {message}")
        with open("honeypot_logs.txt", "a") as log_file:
            log_file.write(f"{time.ctime()} - {client_ip} - {message}\n")

       
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        response += "<html><body><h1>Welcome to the Honeypot!</h1></body></html>"
        ssl_conn.sendall(response.encode())

    except Exception as e:
        print(f"[Honeypot] Error handling client {client_ip}: {e}")
    finally:
        ssl_conn.close()

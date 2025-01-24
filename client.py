from socket import *
import ssl
import sys
import re
import pprint
import traceback
from urllib.parse import urlparse
import requests
import geoip2.database
import getpass

DATABASE_PATH = "./GeoLite2-City.mmdb"

HOST = "127.0.0.1"  # Update this if the server has a public IP
PORT = 8800
FILE = "index.html"
certfile = "./ssl/client_cert.pem"
keyfile = "./ssl/client_key.pem"
cafile = "./ssl/ca_cert.pem"
ssl_version = None
ciphers = None
hostname = "LAPTOP-B5OPK2DN"

def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org")
        response.raise_for_status()
        return response.text.strip()
    except requests.RequestException as e:
        print(f"Error fetching public IP: {e}")
        return None

# Function to fetch GeoIP location
def get_geo_location(ip_address):
    try:
        with geoip2.database.Reader(DATABASE_PATH) as reader:
            response = reader.city(ip_address)
            country = response.country.name or "Unknown Country"
            city = response.city.name or "Unknown City"
            return country, city
    except Exception as e:
        print(f"GeoIP lookup failed for IP {ip_address}: {e}")
        return "Unknown Country", "Unknown City"

version_dict = {
    "tlsv1.0": ssl.PROTOCOL_TLSv1,
    "tlsv1.1": ssl.PROTOCOL_TLSv1_1,
    "tlsv1.2": ssl.PROTOCOL_TLSv1_2,
    "sslv23": ssl.PROTOCOL_SSLv23,
}

for i in range(1, len(sys.argv)):
    arg = sys.argv[i]
    if re.match(r"[-]{,2}(tlsv|sslv)[0-9.]{,3}", arg, re.I):
        ssl_version = re.sub("-", "", arg)
    if re.match(r"[-]{,2}ciphers", arg, re.I):
        ciphers = sys.argv[i + 1]
    if re.match(r"[-]{,2}cacert", arg, re.I):
        certfile = sys.argv[i + 1]
    if re.match(r"^[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}|localhost$", arg, re.I):
        HOST = arg
    if re.match(r"^[0-9]{,5}$", arg):
        PORT = arg
    if re.match(r"^[0-9a-zA-Z_/]+\.[0-9a-zA-Z-_/]+$", arg, re.I):
        FILE = arg

# SSL wrapping function
def ssl_wrap_socket(sock):
    sslContext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    sslContext.load_cert_chain(certfile, keyfile)
    sslContext.verify_mode = ssl.CERT_REQUIRED
    sslContext.load_verify_locations(cafile)
    if ssl_version is not None and ssl_version in version_dict:
        sslContext.options |= version_dict[ssl_version]
    if ciphers:
        sslContext.set_ciphers(ciphers)
    return sslContext.wrap_socket(sock, server_hostname=hostname)

# Function to follow redirects
def follow_redirect(location):
    parsed_url = urlparse(location)
    redirect_host = parsed_url.hostname
    redirect_port = parsed_url.port or 443 
    redirect_path = parsed_url.path + ("?" + parsed_url.query if parsed_url.query else "")

    clientSocket = socket(AF_INET, SOCK_STREAM)
    sslSocket = ssl_wrap_socket(clientSocket)

    try:
        sslSocket.connect((redirect_host, redirect_port))
        print(f"Redirected to server at {redirect_host}:{redirect_port}")
        redirect_message = f"GET {redirect_path} HTTP/1.1\r\nHost: {redirect_host}\r\n\r\n"
        sslSocket.sendall(redirect_message.encode())

        full_response = ""
        while True:
            reply = sslSocket.recv(1024)
            if not reply:
                break
            full_response += reply.decode()
        print("Honeypot Response:")
        print(full_response)
    except Exception as e:
        print(f"Error during redirection: {e}")
    finally:
        sslSocket.close()


# Prepare a client socket
clientSocket = socket(AF_INET, SOCK_STREAM)

# Wrapping the TCP socket with the SSL/TLS context
sslSocket = ssl_wrap_socket(clientSocket)

try:
    # Fetch public IP and location
    public_ip = get_public_ip()
    if public_ip:
        country, city = get_geo_location(public_ip)
        print(f"Public IP: {public_ip}, Country: {country}, City: {city}")
    else:
        country, city = "Unknown Country", "Unknown City"

    password = getpass.getpass("Enter your password: ")
    # Prepare HTTP header
    message = (
        f"GET /{FILE} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        f"X-Country: {country}\r\n"
        f"X-City: {city}\r\n"
        f"X-Password: {password}\r\n"
        f"\r\n"
    )
    
    #SQL Injection
    # message = (
    # f"GET /index.html?username=' OR '1'='1' HTTP/1.1\r\n"
    # f"Host: localhost\r\n"
    # f"X-Country: {country}\r\n"
    # f"X-City: {city}\r\n"
    # f"X-Password: {password}\r\n"
    # f"\r\n"
    # )  
    
    #XSS
    # message = (
    # f"GET /index.html?input=<script>alert('XSS');</script> HTTP/1.1\r\n"
    # f"Host: localhost\r\n"
    # f"X-Country: {country}\r\n"
    # f"X-City: {city}\r\n"
    # f"X-Password: {password}\r\n"
    # f"\r\n"
    # )
    
    # Directory Traversal
    # message = (
    # f"GET /../../../etc/passwd HTTP/1.1\r\n"
    # f"Host: localhost\r\n"
    # f"X-Country: {country}\r\n"
    # f"X-City: {city}\r\n"
    # f"X-Password: {password}\r\n"
    # f"\r\n"
    # ) 
    sslSocket.connect((HOST, int(PORT)))
    print(f"Connected to server at {HOST}:{PORT}")
    sslSocket.sendall(message.encode())

   
    full_response = ""
    while True:
        reply = sslSocket.recv(1024)
        if not reply:
            break
        full_response += reply.decode()

   
    if "302 Found" in full_response:
        print("Redirect detected.")
        location_match = re.search(r"Location: (.+)", full_response)
        if location_match:
            redirect_location = location_match.group(1).strip()
            print(f"Following redirect to {redirect_location}")
            follow_redirect(redirect_location)
    elif "429 Too Many Requests" in full_response:
        print("You have accessed this server more than the rate limit.")
    else:
        print(full_response)

except ConnectionError as ce:
    print("Connection error:", str(ce))

except ssl.SSLError as ssl_e:
    print("SSL error:", str(ssl_e))

except Exception as e:
    print("ERROR:", str(e))

finally:
    try:
        sslSocket.close()
        print("Connection closed.")
    except Exception as e:
        print("Error closing socket:", str(e))










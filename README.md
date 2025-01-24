# SecureTLSWebServer

A Python-based secure web server that uses SSL/TLS for secure communication, implements rate limiting, intrusion detection, and integrates a real-time live dashboard for monitoring connections.

## Features

- **TLS/SSL Security**: Ensures secure communication using TLS certificates.
- **Rate Limiting**: Protects against abuse by limiting requests per client.
- **Intrusion Detection**: Detects potential malicious patterns such as SQL injections, XSS, and more.
- **Honeypot Redirection**: Redirects potential attackers to a honeypot server for further analysis.
- **Live Dashboard**: Displays real-time connection details including IP address, TLS version, cipher, rate-limit status, and geographical location.
- **Client Authentication**: Verifies clients using a password-based authentication system.
- **Comprehensive Logging**: Logs all activity, including intrusion attempts, in a JSON file for audit and analysis.


## Prerequisites

- Python 3.8+
- `rich` library for the live dashboard (`pip install rich`)

## Setup

1. **Generate SSL Certificates**  
   Use the following commands to generate the required certificates and keys:
   ```bash
   openssl req -x509 -newkey rsa:4096 -days 365 -nodes -keyout ./ssl/ca_key.pem -out ./ssl/ca_cert.pem -subj "/CN=My CA"
   openssl req -newkey rsa:4096 -nodes -keyout ./ssl/server_key.pem -out ./ssl/server.csr -subj "/CN=127.0.0.1"
   openssl x509 -req -days 365 -in ./ssl/server.csr -CA ./ssl/ca_cert.pem -CAkey ./ssl/ca_key.pem -set_serial 01 -out ./ssl/server_cert.pem


Install Dependencies

Install the required Python libraries:
pip install rich

Run the Server
Start the server:
python server.py

Access the Server
Connect to the server using a TLS-capable client (e.g., a browser or curl) at https://<HOST>:<PORT>.

Features Breakdown
1. Rate Limiting
Prevents abuse by limiting requests from individual IPs. Configurable using the request_limits dictionary.

2. Intrusion Detection
Detects malicious patterns such as:

SQL Injection: DROP TABLE
Cross-Site Scripting (XSS): <script>
3. Honeypot Redirection
Redirects clients exhibiting malicious behavior to a specified honeypot server.

4. Live Dashboard
Real-time monitoring of active connections using the rich library. Displays:

IP Address
Connection Status
TLS Details
Rate Limiting Status
City and Country (if provided)

import ssl

# Path to the certificate
cert_path = './ssl/ca_cert.pem'

# Load the certificate
cert = ssl._ssl._test_decode_cert(cert_path)

# Print relevant fields
print("Subject:", cert.get('subject'))
print("Issuer:", cert.get('issuer'))
print("SAN:", cert.get('subjectAltName'))
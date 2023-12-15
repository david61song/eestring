#!/bin/bash
#
#
clear
echo "###############################################################################"
echo "-------------------------------------------------------------------------------"
echo "Generating Root cert and server cert. Server cert will be signed by Root cert."
echo "If Server cert had not been signed by Root cert, EEstring Client will break the handshake."
echo "Root cert and Server cert is self-signed cert"
echo "Generating.."
echo "-------------------------------------------------------------------------------"
echo "###############################################################################"
echo 

# Generating Root Certificate and its secret key.
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=KR/ST=Seoul/L=Seoul/O=EEstring/OU=EEstring/CN=EEstringroot" -keyout rootcert.key -out rootcert.pem > /dev/null 2>&1

# Generating Server Certificate
openssl genrsa -out serverkey.pem 4096

# Generating Server Certificate CSR
openssl req -new -key serverkey.pem -subj "/C=KR/ST=Seoul/L=Seoul/O=EEstring/OU=EEstring/CN=EEstringserver" -out server.csr

# Sign Server Certificate by Root cert
openssl x509 -req -in server.csr -CA rootcert.pem -CAkey rootcert.key -CAcreateserial -out servercert.pem -days 365 -sha256

# Clean up
rm server.csr


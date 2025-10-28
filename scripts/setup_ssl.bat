
# Generate SSL certificates for NIDS
openssl genrsa -out certs/nids.key 2048
openssl req -new -key certs/nids.key -out certs/nids.csr -subj "/C=US/ST=State/L=City/O=NIDS/CN=localhost"
openssl x509 -req -days 365 -in certs/nids.csr -signkey certs/nids.key -out certs/nids.crt

#!/bin/sh
# Create an isolated local CA and a localhost server certificate; install no trust roots.
set -eu
umask 077
: "${1:?Usage: create-local-tls.sh NEW_DIRECTORY}"
cert_dir=$1
mkdir "$cert_dir"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 7 \
  -subj '/CN=vIRCd Local Test CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -keyout "$cert_dir/ca.key" -out "$cert_dir/ca.pem"
openssl req -newkey rsa:2048 -nodes -sha256 -subj '/CN=localhost' \
  -keyout "$cert_dir/server.key" -out "$cert_dir/server.csr"
cat > "$cert_dir/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in "$cert_dir/server.csr" -CA "$cert_dir/ca.pem" \
  -CAkey "$cert_dir/ca.key" -CAcreateserial -days 7 -sha256 \
  -extfile "$cert_dir/server.ext" -out "$cert_dir/server.pem"
openssl verify -x509_strict -purpose sslserver -verify_hostname localhost \
  -CAfile "$cert_dir/ca.pem" "$cert_dir/server.pem"

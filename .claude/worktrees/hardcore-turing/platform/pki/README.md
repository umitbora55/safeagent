# PKI Dev Kit

This folder contains dev/test certificates for mTLS. Do not use in production.

## Generation Commands

```bash
# CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -subj "/CN=SafeAgent Dev CA" -out ca.crt

# Control plane cert
openssl genrsa -out control-plane.key 2048
openssl req -new -key control-plane.key -out control-plane.csr -config openssl-control-plane.cnf
openssl x509 -req -in control-plane.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out control-plane.crt -days 365 -sha256 -extfile openssl-control-plane.cnf -extensions v3_req

# Worker cert
openssl genrsa -out worker.key 2048
openssl req -new -key worker.key -out worker.csr -config openssl-worker.cnf
openssl x509 -req -in worker.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out worker.crt -days 365 -sha256 -extfile openssl-worker.cnf -extensions v3_req
```

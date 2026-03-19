listen = "0.0.0.0:9999"

api {
  listen  = "127.0.0.1:9443"
  api_key = "test-key-123"

  tls {
    certificate = "certs/api-cert.pem"
    key         = "certs/api-key.pem"
  }
}

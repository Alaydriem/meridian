listen = "0.0.0.0:4433"
cid_prefix_length = 2
workers = 6

api {
  listen  = "0.0.0.0:9443"
  api_key = "test-api-key"

  tls {
    certificate = "/certs/api-cert.pem"
    key         = "/certs/api-key.pem"
  }
}

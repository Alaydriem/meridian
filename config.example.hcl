listen = "0.0.0.0:443"
cid_prefix_length = 2

api {
  listen  = "0.0.0.0:9443"
  api_key = "your-secret-api-key"

  tls {
    certificate = "/etc/meridian/api-cert.pem"
    key         = "/etc/meridian/api-key.pem"
  }
}

backend "server1" {
  hostname    = "server1.localhost"
  tcp_addr    = "server-1:443"
  udp_addr    = "server-1:8443"
  instance_id = 1
}

backend "server2" {
  hostname    = "server2.localhost"
  tcp_addr    = "server-2:443"
  udp_addr    = "server-2:443"
  instance_id = 2
}

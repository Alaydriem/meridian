# Meridian

A high-performance, QUIC-aware SNI proxy written in Rust.

Meridian routes both TCP (HTTPS) and UDP (QUIC) traffic to backend servers based on SNI (Server Name Indication) hostnames. It decrypts QUIC Initial packets to extract SNI without per-connection TLS termination, and uses Connection ID prefix routing for subsequent QUIC packets — giving you transparent, zero-overhead proxying for both protocols on a single port.

## Features

- **Dual-protocol routing** — TCP and UDP on the same listen address
- **QUIC Initial decryption** — extracts SNI from QUIC ClientHello without terminating TLS
- **CID prefix routing** — routes subsequent QUIC packets by Connection ID prefix for near-zero lookup cost
- **CRYPTO frame reassembly** — handles fragmented QUIC ClientHellos across multiple Initial packets
- **Control plane API** — HTTPS API for dynamic backend registration, updates, and removal at runtime
- **Bearer-token authentication** — API key middleware protects all control plane endpoints
- **HCL configuration** — human-friendly config format with static backend definitions
- **Built-in CLI** — manage backends and health-check a running instance without cURL
- **Dual crate features** — use `server`, `client`, or both as a library in your own application

## Architecture

```
                           ┌─────────────────────────┐
                           │        Meridian          │
  Client ──TCP (TLS)──────►│  TcpRouter: peek SNI ───┼──► Backend A (tcp_addr)
                           │                          │
  Client ──UDP (QUIC)─────►│  UdpRouter:              │
                           │    Initial → decrypt SNI ┼──► Backend B (udp_addr)
                           │    Short   → CID prefix  │
                           │                          │
  Admin ──HTTPS────────────►│  ControlPlane: REST API  │
                           └─────────────────────────┘
```

**TCP flow:** Accept connection, peek at TLS ClientHello, extract SNI hostname, look up backend in the routing table, and bidirectionally proxy the connection.

**UDP flow:** For QUIC Initial packets, decrypt the CRYPTO payload and parse the ClientHello to extract SNI. Map the client to a backend and cache the association. For subsequent Short Header packets, read the CID prefix bytes to resolve the backend's `instance_id` directly — no decryption needed.

---

## Running the Server

### Docker

Build the image:

```bash
docker build -t meridian .
```

Run with a config file and TLS certificates mounted:

```bash
docker run \
  -v ./config.hcl:/etc/meridian/config.hcl:ro \
  -v ./certs:/etc/meridian:ro \
  -p 443:443 \
  -p 443:443/udp \
  -p 9443:9443 \
  meridian
```

- **Port 443 (TCP+UDP)** — proxy traffic (HTTPS and QUIC)
- **Port 9443** — control plane API

### Docker Compose

```yaml
version: "3.8"

services:
  meridian:
    build: .
    ports:
      - "443:443"
      - "443:443/udp"
      - "9443:9443"
    volumes:
      - ./config.hcl:/etc/meridian/config.hcl:ro
      - ./certs:/etc/meridian:ro
    depends_on:
      - backend-1
      - backend-2

  backend-1:
    image: your-backend-server:latest
    environment:
      - INSTANCE_ID=1
      - QUIC_PORT=8443

  backend-2:
    image: your-backend-server:latest
    environment:
      - INSTANCE_ID=2
      - QUIC_PORT=8443
```

### From Source

```bash
cargo build --release
./target/release/meridian --config config.hcl
```

The `--config` flag defaults to `config.hcl` in the working directory if omitted.

---

## CLI

Meridian includes a built-in CLI for managing a running instance without needing cURL or other HTTP tools in the container.

### Health Check

Verify a running instance is alive and its API is responsive:

```bash
meridian --config config.hcl health
# Meridian is healthy. 3 backend(s) registered.
```

The health check exercises the full API path (TLS + authentication + routing table read). The exit code is `0` on success, `1` on failure, making it suitable for container `HEALTHCHECK` directives.

### Backend Management

```bash
# List all backends
meridian backend list

# Add a backend
meridian backend add server1 \
  --hostname server1.example.com \
  --tcp-addr 10.0.0.1:443 \
  --udp-addr 10.0.0.1:8443 \
  --instance-id 1

# Update a backend
meridian backend update server1 \
  --hostname server1-new.example.com \
  --tcp-addr 10.0.0.2:443 \
  --udp-addr 10.0.0.2:8443 \
  --instance-id 1

# Remove a backend
meridian backend remove server1
```

### Global Flags

| Flag | Description |
|---|---|
| `--config <path>` | Path to HCL config file (default: `config.hcl`) |
| `--insecure` | Skip TLS certificate verification when connecting to the API |

The CLI reads the `api` block from `config.hcl` to determine the API address, authentication key, and TLS trust. The `--insecure` flag is useful for development with self-signed certificates.

---

## Configuration

Meridian uses [HCL](https://github.com/hashicorp/hcl) for configuration.

```hcl
# Address to listen on for proxied TCP + UDP traffic.
listen = "0.0.0.0:443"

# Number of bytes at the start of each QUIC Connection ID that encode the
# backend instance_id. Backends must embed their instance_id in this prefix.
# Default: 2
cid_prefix_length = 2

# Optional: control plane API for dynamic backend management.
api {
  listen  = "0.0.0.0:9443"
  api_key = "your-secret-api-key"

  tls {
    certificate = "/etc/meridian/api-cert.pem"
    key         = "/etc/meridian/api-key.pem"
  }
}

# Static backend definitions (loaded at startup).
backend "server1" {
  hostname    = "server1.example.com"    # SNI hostname to match
  tcp_addr    = "10.0.0.1:443"           # Forward HTTPS traffic here
  udp_addr    = "10.0.0.1:8443"          # Forward QUIC traffic here
  instance_id = 1                        # CID prefix value (u16)
}

backend "server2" {
  hostname    = "server2.example.com"
  tcp_addr    = "10.0.0.2:443"
  udp_addr    = "10.0.0.2:8443"
  instance_id = 2
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `listen` | `String` | Yes | Socket address for proxy traffic |
| `cid_prefix_length` | `u8` | No (default `2`) | Bytes of CID reserved for instance routing |
| `api.listen` | `String` | No | Socket address for the control plane |
| `api.api_key` | `String` | If `api` set | Bearer token for API authentication |
| `api.tls.certificate` | `String` | If `api` set | Path to PEM certificate for API TLS |
| `api.tls.key` | `String` | If `api` set | Path to PEM private key for API TLS |
| `backend.<name>.hostname` | `String` | Yes | SNI hostname to route |
| `backend.<name>.tcp_addr` | `String` | Yes | Backend address for TCP traffic |
| `backend.<name>.udp_addr` | `String` | Yes | Backend address for UDP traffic |
| `backend.<name>.instance_id` | `u16` | Yes | CID prefix value for QUIC routing |

---

## Control Plane API

All endpoints require a `Authorization: Bearer <api_key>` header. The API is served over HTTPS.

### Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/backends` | List all registered backends |
| `POST` | `/backends` | Register a new backend |
| `PUT` | `/backends/{name}` | Update an existing backend |
| `DELETE` | `/backends/{name}` | Remove a backend |

### Request / Response Shapes

**POST /backends** — Create

```json
// Request
{
  "name": "server1",
  "hostname": "server1.example.com",
  "tcp_addr": "10.0.0.1:443",
  "udp_addr": "10.0.0.1:8443",
  "instance_id": 1
}

// Response (201 Created)
{
  "name": "server1",
  "hostname": "server1.example.com",
  "tcp_addr": "10.0.0.1:443",
  "udp_addr": "10.0.0.1:8443",
  "instance_id": 1
}
```

**PUT /backends/{name}** — Update

```json
// Request
{
  "hostname": "server1-new.example.com",
  "tcp_addr": "10.0.0.3:443",
  "udp_addr": "10.0.0.3:8443",
  "instance_id": 1
}

// Response (200 OK)
{
  "name": "server1",
  "hostname": "server1-new.example.com",
  "tcp_addr": "10.0.0.3:443",
  "udp_addr": "10.0.0.3:8443",
  "instance_id": 1
}
```

**GET /backends** — List

```json
// Response (200 OK)
{
  "backends": [
    {
      "name": "server1",
      "hostname": "server1.example.com",
      "tcp_addr": "10.0.0.1:443",
      "udp_addr": "10.0.0.1:8443",
      "instance_id": 1
    }
  ]
}
```

**DELETE /backends/{name}** — Remove

Returns `204 No Content` on success, `404 Not Found` if the backend doesn't exist.

### Error Response

```json
{
  "error": "backend 'server1' not found"
}
```

---

## Library Integration: Client

Use the `client` feature to interact with a running Meridian control plane from your application.

**Cargo.toml:**

```toml
[dependencies]
meridian = { path = "../meridian", default-features = false, features = ["client"] }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
```

**Usage:**

```rust
use meridian::api::MeridianClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Build the client — provide the API base URL and your API key.
    // Use with_ca_cert_file() for self-signed certs, or
    // danger_accept_invalid_certs(true) for development.
    let client = MeridianClient::builder("https://127.0.0.1:9443", "your-secret-api-key")
        .with_ca_cert_file("certs/ca.pem")?
        .build()?;

    // Register a new backend (takes effect immediately for routing)
    let backend = client.register(
        "game-server-3",           // name
        "gs3.example.com",         // hostname (SNI to match)
        "10.0.0.3:443",            // tcp_addr
        "10.0.0.3:8443",           // udp_addr
        3,                         // instance_id (CID prefix)
    ).await?;
    println!("registered: {}", backend.name);

    // List all backends
    let backends = client.list_backends().await?;
    for b in &backends {
        println!("{}: {} -> tcp={}, udp={}", b.name, b.hostname, b.tcp_addr, b.udp_addr);
    }

    // Update a backend
    client.update_backend(
        "game-server-3",
        "gs3-updated.example.com",
        "10.0.0.30:443",
        "10.0.0.30:8443",
        3,
    ).await?;

    // Remove a backend
    client.remove_backend("game-server-3").await?;

    Ok(())
}
```

### Client Builder Options

| Method | Description |
|---|---|
| `MeridianClient::builder(base_url, api_key)` | Create a new builder |
| `.with_ca_cert_file(path)` | Trust a PEM CA certificate file (for self-signed API certs) |
| `.with_ca_cert_pem(bytes)` | Trust a PEM CA certificate from bytes |
| `.danger_accept_invalid_certs(true)` | Skip TLS verification (development only) |
| `.build()` | Build the `MeridianClient` |

---

## Library Integration: Server

Use the `server` feature to embed the Meridian proxy engine into your own application.

**Cargo.toml:**

```toml
[dependencies]
meridian = { path = "../meridian", default-features = false, features = ["server"] }
tokio = { version = "1", features = ["full"] }
tokio-util = "0.7"
tracing-subscriber = "0.3"
anyhow = "1"
```

### From a Config File

```rust
use meridian::MeridianBuilder;
use meridian::config::parse_config_file;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = parse_config_file("config.hcl")?;
    let meridian = MeridianBuilder::new(config).build().await?;

    let shutdown = CancellationToken::new();
    let token = shutdown.clone();

    // Shut down gracefully on Ctrl-C
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        token.cancel();
    });

    meridian.run(shutdown).await
}
```

### From an HCL String

```rust
use meridian::MeridianBuilder;
use meridian::config::parse_config;

let hcl = r#"
    listen = "0.0.0.0:443"
    cid_prefix_length = 2

    backend "web" {
        hostname    = "web.example.com"
        tcp_addr    = "10.0.0.1:443"
        udp_addr    = "10.0.0.1:8443"
        instance_id = 1
    }
"#;

let config = parse_config(hcl)?;
let meridian = MeridianBuilder::new(config).build().await?;
```

### Programmatic Configuration

```rust
use std::collections::HashMap;
use meridian::MeridianBuilder;
use meridian::config::{MeridianConfig, BackendConfig, ApiConfig, TlsConfig};

let config = MeridianConfig {
    listen: "0.0.0.0:443".to_string(),
    cid_prefix_length: 2,
    api: Some(ApiConfig {
        listen: "0.0.0.0:9443".to_string(),
        api_key: "my-secret".to_string(),
        tls: TlsConfig {
            certificate: "certs/api-cert.pem".to_string(),
            key: "certs/api-key.pem".to_string(),
        },
    }),
    backend: HashMap::from([
        ("server1".to_string(), BackendConfig {
            hostname: "server1.example.com".to_string(),
            tcp_addr: "10.0.0.1:443".to_string(),
            udp_addr: "10.0.0.1:8443".to_string(),
            instance_id: 1,
        }),
    ]),
};

let meridian = MeridianBuilder::new(config).build().await?;
```

### Accessing the Routing Table

The `Meridian` instance exposes its routing table for direct inspection:

```rust
let meridian = MeridianBuilder::new(config).build().await?;

// Read the current routing table
let table = meridian.routing_table();
if let Some(backend) = table.get_by_hostname("server1.example.com") {
    println!("routes to tcp={}, udp={}", backend.tcp_addr, backend.udp_addr);
}
```

---

## Examples

The `examples/` directory includes utilities for testing and benchmarking.

### Generate Test Certificates

Creates a CA and server certificates in `certs/`:

```bash
cargo run --example gen_certs
```

### Run a Test Backend

Starts an HTTPS + QUIC backend server that auto-registers with the control plane:

```bash
cargo run --example backend -- \
  --id 1 \
  --tcp_port 4433 \
  --udp_port 4434 \
  --api https://127.0.0.1:9443 \
  --api_key your-secret-api-key \
  --certs_dir certs
```

### Run the Test Client

Connects through the proxy to verify routing:

```bash
cargo run --example client -- \
  --proxy 127.0.0.1:443 \
  --sni server1.example.com \
  --certs_dir certs
```

Flags `--https_only` and `--quic_only` are available to test individual protocols.

### Throughput Benchmark

Runs a high-throughput load test measuring latency and packet loss:

```bash
cargo run --example throughput -- \
  --proxy 127.0.0.1:443 \
  --sni server1.example.com \
  --rate 1000 \
  --duration 30 \
  --certs_dir certs
```

---

## Testing

```bash
cargo test
```

The test suite includes:

- **Control plane tests** — CRUD operations, authentication enforcement, error handling
- **TCP passthrough tests** — SNI-based routing, unknown SNI rejection

Tests generate self-signed certificates automatically and bind to ephemeral ports, so no setup is required.

---

## License

<!-- TODO: Add license -->

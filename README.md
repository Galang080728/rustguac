# rustguac

A lightweight Rust replacement for the Apache Guacamole Java webapp. Provides browser-based SSH, RDP, and web browsing sessions through [guacd](https://github.com/apache/guacamole-server) (the Guacamole protocol daemon).

rustguac sits between web browsers and guacd, proxying the Guacamole protocol over WebSockets. It manages session lifecycle, authentication (API keys and OIDC SSO), session recording, and browser-based VNC sessions (Xvnc + Chromium).

## Features

- **SSH sessions** — browser-based SSH terminal via guacd, with ephemeral keypair or manual private key auth
- **RDP sessions** — connect to Windows/RDP hosts via guacd
- **Web browser sessions** — headless Chromium on Xvnc, streamed to the browser via VNC
- **OIDC single sign-on** — authenticate users via any OpenID Connect provider (JumpCloud, Google, Okta, etc.)
- **Role-based access** — admin, operator, and viewer roles for both API key and OIDC users
- **TLS everywhere** — HTTPS for clients, TLS between rustguac and guacd (both enabled by default)
- **Session recording** — all sessions recorded in Guacamole format with playback UI
- **Session sharing** — share tokens for read-only or collaborative access
- **API key auth** — SHA-256 hashed keys with IP allowlists and expiry
- **Pre-session banners** — configurable banner text shown before session starts
- **SQLite storage** — no external database server needed
- **Single binary** — just rustguac + guacd, no Java stack

## Architecture

```
Browser (HTML/JS)
    |
    | WebSocket over HTTPS
    v
rustguac (Rust, axum)
    |
    | TLS (Guacamole protocol)
    v
guacd (C, from guacamole-server)
    |
    +---> SSH server (for SSH sessions)
    +---> RDP server (for RDP sessions)
    +---> Xvnc display (for web browser sessions)
              |
              +---> Chromium (kiosk mode)
```

Both links are encrypted by default: HTTPS between browsers and rustguac, TLS between rustguac and guacd.

## Ports

| Port | Service |
|------|---------|
| 443 | rustguac HTTPS (default with TLS) |
| 8089 | rustguac HTTP (when TLS is disabled) |
| 4822 | guacd (TLS-encrypted, loopback only) |
| 6000-6099 | Xvnc displays (`:100`-`:199`, internal) |

## Installation

### Option A: Bare-metal Debian 13

```bash
sudo ./install.sh
```

This builds guacd from source (with patches for FreeRDP 3.x compatibility applied automatically), builds rustguac, generates a self-signed TLS certificate, and installs everything to `/opt/rustguac` with systemd services. The rustguac-to-guacd connection is TLS-encrypted by default.

Flags:

- `--no-tls` — skip TLS cert generation, listen on HTTP port 8089
- `--hostname=FQDN` — hostname for the TLS certificate (default: system hostname)
- `--deps-only` — only install system packages
- `--no-deps` — skip apt install

After install:

```bash
# Create an admin and get an API key
/opt/rustguac/bin/rustguac --config /opt/rustguac/config.toml add-admin --name admin

# Start the services (starts both guacd and rustguac)
sudo systemctl start rustguac
```

### Option B: Docker

```bash
docker pull sol1/rustguac:latest
docker run -d -p 8089:8089 sol1/rustguac:latest
```

Pre-built images are available on [Docker Hub](https://hub.docker.com/r/sol1/rustguac). To build from source instead:

```bash
docker build -t rustguac .
docker run -d -p 8089:8089 rustguac
```

The Docker image generates a self-signed cert at build time and enables TLS between rustguac and guacd by default. The external-facing port is HTTP on 8089 (put a reverse proxy in front for HTTPS in production).

### Option C: Development

```bash
# Clone guacamole-server alongside rustguac
git clone https://github.com/apache/guacamole-server.git ../guacamole-server

# Install build deps, build guacd (patches applied automatically), build + run rustguac
./dev.sh deps
./dev.sh build-guacd
./dev.sh start
```

If a `config.local.toml` file exists in the project root, `dev.sh run` and `dev.sh start` will use it automatically:

```bash
# Generate self-signed TLS cert for dev
./dev.sh generate-cert

cat > config.local.toml <<EOF
[tls]
cert_path = "cert.pem"
key_path = "key.pem"
guacd_cert_path = "cert.pem"
EOF

./dev.sh start
```

## Configuration

rustguac reads a TOML config file (default: `config.local.toml`, or specify with `--config`).

```toml
listen_addr = "0.0.0.0:443"
guacd_addr = "127.0.0.1:4822"
recording_path = "/opt/rustguac/recordings"
static_path = "/opt/rustguac/static"
db_path = "/opt/rustguac/data/rustguac.db"
session_pending_timeout_secs = 60
session_max_duration_secs = 28800  # 8 hours
site_title = "rustguac"

# Browser session settings
xvnc_path = "Xvnc"
chromium_path = "chromium"
display_range_start = 100
display_range_end = 199
```

All settings have defaults and are optional. See `config.example.toml` for a fully documented reference.

### Connection allowlists

Control which hosts sessions can connect to. Each setting is a list of CIDR ranges. All three default to localhost only (`127.0.0.0/8` and `::1/128`).

**Important:** These are top-level TOML keys and must appear *before* any `[section]` header (e.g. `[tls]`, `[oidc]`). In TOML, any key after a `[section]` header is scoped to that section, so placing these under `[tls]` will silently ignore them and the defaults (localhost only) will be used.

```toml
# Allow SSH sessions to reach any private network host
ssh_allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "192.168.0.0/16"]

# Allow RDP to a specific subnet
rdp_allowed_networks = ["10.0.5.0/24"]

# Allow web browser sessions to reach any host
web_allowed_networks = ["0.0.0.0/0", "::/0"]
```

For SSH and RDP sessions, the target hostname is resolved and checked against the allowlist. For web sessions, the URL's hostname is resolved and checked. If resolution returns multiple addresses, at least one must be in the allowlist.

### TLS

The `[tls]` section controls both HTTPS for clients and TLS encryption to guacd:

```toml
[tls]
cert_path = "/opt/rustguac/tls/cert.pem"       # HTTPS certificate
key_path = "/opt/rustguac/tls/key.pem"          # HTTPS private key
guacd_cert_path = "/opt/rustguac/tls/cert.pem"  # trust this cert for guacd connection
```

- `cert_path` + `key_path` — enables HTTPS. Omit the entire `[tls]` section for plain HTTP.
- `guacd_cert_path` — when set, rustguac connects to guacd over TLS, trusting this certificate. The same self-signed cert can serve both purposes. Omit for plain TCP to guacd.

guacd must also be started with TLS flags to match:

```bash
guacd -b 127.0.0.1 -l 4822 -L info -f -C /opt/rustguac/tls/cert.pem -K /opt/rustguac/tls/key.pem
```

The install script and Docker image configure this automatically. Both sides must agree: either both TLS or both plain TCP.

Generate a self-signed certificate:

```bash
rustguac generate-cert --hostname your-hostname.example.com --out-dir /opt/rustguac/tls
```

### OIDC

To enable OpenID Connect single sign-on, add an `[oidc]` section:

```toml
[oidc]
issuer_url = "https://oauth.id.jumpcloud.com/"
client_id = "your-client-id"
client_secret = "your-client-secret"
redirect_uri = "https://your-host/auth/callback"
default_role = "operator"  # role assigned to new users (default: "operator")
```

Works with any OIDC provider: JumpCloud, Google, Okta, Azure AD, Keycloak, etc. Configure your provider with the redirect URI `https://your-host/auth/callback`.

The `client_secret` can also be provided via the `OIDC_CLIENT_SECRET` environment variable, which takes precedence over the config file. This is recommended for production (Docker, systemd `EnvironmentFile`, etc.).

**Roles:**

| Role | Level | Permissions |
|------|-------|-------------|
| admin | 4 | Full access: manage users, address book, recordings, sessions, group mappings |
| poweruser | 3 | Ad-hoc session creation + address book connect |
| operator | 2 | Address book connect only (no ad-hoc sessions) |
| viewer | 1 | Read-only: view sessions and recordings |

New OIDC users are assigned `default_role` on first login. Admins can change roles via CLI, API, or the web Admin page.

**Group-to-role mappings:** Admins can configure automatic role assignment based on OIDC group membership in the Admin page. Mappings are evaluated on every OIDC login — the highest matching role wins. If no mappings match, the existing role is preserved.

Admins can change roles:

```bash
# CLI
rustguac set-role --email user@example.com --role admin

# Or via API
curl -X PUT https://host/api/users/user@example.com/role \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
```

User management commands:

```bash
rustguac list-users
rustguac set-role --email user@example.com --role operator
rustguac disable-user --email user@example.com
rustguac delete-user --email user@example.com
```

When OIDC is configured, the web UI shows a login button that redirects to the provider. API key auth continues to work alongside OIDC.

### Address Book (Vault)

The address book stores connection entries (SSH, RDP, Web) in [HashiCorp Vault](https://www.vaultproject.io/) or [OpenBao](https://openbao.org/) KV v2. Credentials never reach the browser — rustguac reads them from Vault server-side and creates sessions directly.

**1. Enable KV v2** (skip if already enabled):

```bash
vault secrets enable -path=secret kv-v2
```

**2. Create a Vault policy** for rustguac:

```bash
vault policy write rustguac - <<'EOF'
# Allow rustguac to manage address book entries
path "secret/data/rustguac/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/rustguac/*" {
  capabilities = ["list", "read", "delete"]
}
EOF
```

Adjust `secret` and `rustguac` if you use a different mount or base_path.

**3. Enable AppRole auth** and create a role:

```bash
vault auth enable approle

vault write auth/approle/role/rustguac \
    token_policies="rustguac" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0

# Get the role_id (put this in config.toml)
vault read auth/approle/role/rustguac/role-id

# Generate a secret_id (set as VAULT_SECRET_ID env var)
vault write -f auth/approle/role/rustguac/secret-id
```

**4. Configure rustguac** — add a `[vault]` section:

```toml
[vault]
addr = "https://vault.example.com:8200"
role_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# mount = "secret"          # KV v2 mount (default: "secret")
# base_path = "rustguac"    # base path under mount (default: "rustguac")
# namespace = "my-ns"       # optional, Vault Enterprise / OpenBao namespaces
# instance_name = "prod-1"  # optional, enables instance-scoped entries
```

Set the environment variable:

```bash
export VAULT_SECRET_ID="<secret_id from step 3>"
```

For systemd, add it to an `EnvironmentFile`:

```bash
echo 'VAULT_SECRET_ID=<secret_id>' > /opt/rustguac/env
chmod 600 /opt/rustguac/env
# In the systemd unit: EnvironmentFile=/opt/rustguac/env
```

**5. Manage via the UI.** Admins can create folders (with OIDC group access controls) and connection entries in the Address Book page. Operators can connect to entries in folders their groups have access to.

**Vault KV v2 path structure:**

| Path | Description |
|------|-------------|
| `rustguac/shared/<folder>/.config` | Folder metadata: `{"allowed_groups":[...], "description":"..."}` |
| `rustguac/shared/<folder>/<entry>` | Connection entry (shared across all instances) |
| `rustguac/instance/<name>/<folder>/<entry>` | Instance-specific entry (requires `instance_name` in config) |

## Admin management

API key admins always have full admin-level access.

```bash
# Add an admin (prints the API key — save it)
rustguac add-admin --name myadmin

# Restrict to specific IPs
rustguac add-admin --name myadmin --allowed-ips "10.0.0.0/8,192.168.1.0/24"

# Set expiry
rustguac add-admin --name myadmin --expires "2026-12-31T00:00:00Z"

# List / disable / enable / rotate / delete
rustguac list-admins
rustguac disable-admin --name myadmin
rustguac enable-admin --name myadmin
rustguac rotate-key --name myadmin
rustguac delete-admin --name myadmin
```

## API usage

Create an SSH session (password auth):

```bash
curl -X POST https://localhost/api/sessions \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "session_type": "ssh",
    "hostname": "10.0.0.1",
    "port": 22,
    "username": "root",
    "password": "secret"
  }'
```

### SSH ephemeral keypair

Instead of passwords, rustguac can generate a one-time Ed25519 keypair per session. The flow:

1. Create the session with `"generate_keypair": true`
2. Open the session URL (or send the share link — recipients also see the banner)
3. The banner displays the public key with a "Copy public key" button — copy it and add to the user's `authorized_keys` on the target host
4. Click "Continue" — **only then** does rustguac connect to guacd and attempt SSH auth with the ephemeral key
5. The private key only exists in memory during the handshake. It is never stored on disk or returned by the API.

The SSH connection is intentionally deferred — guacd does not contact the target host until Continue is clicked, giving time to install the key. This works well with share links: create the session, send the share URL to the person who controls the target host, they install the key and click Continue.

```bash
curl -X POST https://localhost/api/sessions \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "session_type": "ssh",
    "hostname": "10.0.0.1",
    "username": "root",
    "generate_keypair": true
  }'
```

You can also paste an existing OpenSSH private key via the `"private_key"` field instead of using ephemeral generation.

Create an RDP session:

```bash
curl -X POST https://localhost/api/sessions \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "session_type": "rdp",
    "hostname": "10.0.0.1",
    "port": 3389,
    "username": "Administrator",
    "password": "secret",
    "ignore_cert": true
  }'
```

Create a web browser session:

```bash
curl -X POST https://localhost/api/sessions \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "session_type": "web",
    "url": "https://example.com"
  }'
```

The response includes `client_url` — open it in a browser to use the session.

Other endpoints:

```bash
# List sessions
curl https://localhost/api/sessions -H "Authorization: Bearer <api-key>"

# Delete a session
curl -X DELETE https://localhost/api/sessions/<id> -H "Authorization: Bearer <api-key>"

# List recordings
curl https://localhost/api/recordings -H "Authorization: Bearer <api-key>"

# Health check (no auth)
curl https://localhost/api/health
```

## Docker Compose

Example for integrating with an existing stack:

```yaml
services:
  rustguac:
    image: sol1/rustguac:latest
    ports:
      - "8089:8089"
    volumes:
      - rustguac-data:/opt/rustguac/data
    environment:
      - RUST_LOG=info

volumes:
  rustguac-data:
```

## Building the Docker image

```bash
docker build -t sol1/rustguac:latest .
docker push sol1/rustguac:latest
```

## System dependencies

For bare-metal installs, rustguac requires:

- **Rust toolchain** (1.75+)
- **guacd** (built from [guacamole-server](https://github.com/apache/guacamole-server) source)
- **Xvnc** (tigervnc-standalone-server) — for web browser sessions
- **Chromium** — for web browser sessions
- **Build libraries** for guacd: libcairo2, libjpeg, libpng, libwebp, libssh2, libssl, libvncserver, libpango, libpulse, ffmpeg libs, freerdp3

See `install.sh` for the full package list.

## guacamole-server patches

guacamole-server (guacd) requires patches to build and run correctly with FreeRDP 3.15+ as shipped in Debian 13. These patches are in the `patches/` directory and are applied automatically by all build scripts (`build-deb.sh`, `build-rpm.sh`, `install.sh`, `dev.sh`, and the `Dockerfile`).

The patches fix:
- Autoconf feature detection failures caused by `-Werror` + deprecated FreeRDP headers
- Deprecated function pointer API (`->input->MouseEvent()` etc.) replaced with safe FreeRDP 3.x functions
- NULL pointer dereference in the display update channel when FreeRDP fires events before initialization

See `patches/README.md` for full details. To add new patches, edit `../guacamole-server` and export with `git diff > patches/NNN-description.patch`.

## Project structure

```
src/
  main.rs          Entry point, CLI, server setup
  api.rs           REST API endpoints
  auth.rs          API key + OIDC session authentication middleware
  browser.rs       Xvnc + Chromium process manager
  config.rs        TOML config loading
  db.rs            SQLite database (admins, OIDC users, sessions)
  guacd.rs         guacd TLS/TCP connection & protocol handshake
  oidc.rs          OpenID Connect login flow
  protocol.rs      Guacamole wire format parser
  session.rs       Session state machine
  websocket.rs     WebSocket <-> guacd proxy
static/
  *.html           Web UI pages
  guac/            Guacamole JS client library
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

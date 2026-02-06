# API Reference

All API endpoints are under `/api/`. Authentication is via `Authorization: Bearer <api-key>` header, `X-API-Key: <key>` header, or OIDC session cookie.

## Health

### `GET /api/health`

No authentication required. Returns 200 OK when the server is running.

## Sessions

### `POST /api/sessions`

Create a new session. Requires **poweruser** role or higher.

**SSH session (password):**

```json
{
  "session_type": "ssh",
  "hostname": "10.0.0.1",
  "port": 22,
  "username": "root",
  "password": "secret"
}
```

**SSH session (ephemeral keypair):**

```json
{
  "session_type": "ssh",
  "hostname": "10.0.0.1",
  "username": "root",
  "generate_keypair": true
}
```

The response includes the public key in the `banner_text` field. The SSH connection is deferred until the user clicks "Continue" on the banner page.

**SSH session (private key):**

```json
{
  "session_type": "ssh",
  "hostname": "10.0.0.1",
  "username": "root",
  "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
}
```

**RDP session:**

```json
{
  "session_type": "rdp",
  "hostname": "10.0.0.1",
  "port": 3389,
  "username": "Administrator",
  "password": "secret",
  "ignore_cert": true,
  "domain": "EXAMPLE"
}
```

**Web browser session:**

```json
{
  "session_type": "web",
  "url": "https://example.com"
}
```

**Response:**

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_url": "/client.html?session_id=550e8400-e29b-41d4-a716-446655440000",
  "share_url": "/client.html?session_id=550e8400-e29b-41d4-a716-446655440000&key=abc123"
}
```

### `GET /api/sessions`

List all sessions. Requires **operator** role or higher.

### `GET /api/sessions/:id`

Get session details. Requires **operator** role or higher.

### `DELETE /api/sessions/:id`

Terminate a session. Requires **operator** role or higher. Non-admins can only delete their own sessions.

### `GET /api/sessions/:id/banner`

Get session banner text. Authenticates via share token (not credentials). Used for the ephemeral keypair banner display.

## Recordings

### `GET /api/recordings`

List all recording files. Requires **operator** role or higher.

### `GET /api/recordings/:name`

Serve a recording file for playback. Requires **operator** role or higher. Filename is validated against path traversal.

### `DELETE /api/recordings/:name`

Delete a recording file. Requires **admin** role.

## Users (admin only)

### `GET /api/users`

List all OIDC users.

### `PUT /api/users/:email/role`

Set a user's role.

```json
{
  "role": "poweruser"
}
```

Valid roles: `admin`, `poweruser`, `operator`, `viewer`.

### `DELETE /api/users/:email`

Delete a user.

### `POST /api/users/:email/disable`

Disable a user (blocks login).

### `POST /api/users/:email/enable`

Re-enable a disabled user.

### `DELETE /api/users/:email/sessions`

Force-logout a user by deleting all their auth sessions.

## Group-to-Role Mappings (admin only)

### `GET /api/admin/group-mappings`

List all group-to-role mappings.

### `POST /api/admin/group-mappings`

Create a mapping.

```json
{
  "oidc_group": "engineering",
  "role": "poweruser"
}
```

Returns 409 Conflict if a mapping for the group already exists.

### `PUT /api/admin/group-mappings/:id`

Update a mapping.

```json
{
  "oidc_group": "engineering",
  "role": "admin"
}
```

### `DELETE /api/admin/group-mappings/:id`

Delete a mapping.

## Address Book (requires Vault)

### `GET /api/addressbook/folders`

List visible folders. Filtered by OIDC group membership (admins see all).

### `GET /api/addressbook/folders/:scope/:folder/entries`

List entries in a folder. Scope is `shared` or `instance`. Requires folder group access.

### `POST /api/addressbook/folders/:scope/:folder/entries/:entry/connect`

Create a session from an address book entry. Reads credentials from Vault server-side and creates a session. Requires **operator** role and folder group access.

### `POST /api/addressbook/folders` (admin)

Create a folder.

```json
{
  "scope": "shared",
  "name": "production",
  "allowed_groups": ["engineering", "devops"],
  "description": "Production servers"
}
```

### `PUT /api/addressbook/folders/:scope/:folder` (admin)

Update folder configuration (allowed_groups, description).

### `DELETE /api/addressbook/folders/:scope/:folder` (admin)

Delete a folder and all its entries.

### `POST /api/addressbook/folders/:scope/:folder/entries` (admin)

Create a connection entry.

### `PUT /api/addressbook/folders/:scope/:folder/entries/:entry` (admin)

Update a connection entry.

### `DELETE /api/addressbook/folders/:scope/:folder/entries/:entry` (admin)

Delete a connection entry.

## Authentication

### `GET /api/auth/status`

No authentication required. Returns whether OIDC is enabled and the site title.

```json
{
  "oidc_enabled": true,
  "site_title": "rustguac"
}
```

### `GET /api/me`

Returns current user info. Requires authentication.

```json
{
  "name": "User Name",
  "email": "user@example.com",
  "role": "operator",
  "groups": ["engineering"],
  "auth_type": "oidc",
  "vault_enabled": true,
  "vault_configured": true
}
```

### `GET /auth/login`

Redirects to OIDC provider for authentication.

### `GET /auth/callback`

OIDC callback endpoint. Handles token exchange, user creation/update, and session creation.

### `GET /auth/logout`

Clears the session cookie and deletes the auth session.

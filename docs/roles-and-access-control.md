# Roles and Access Control

## Role hierarchy

rustguac implements a 4-tier role hierarchy:

| Role | Level | Description |
|------|-------|-------------|
| **admin** | 4 | Full access — manage users, address book, recordings, sessions, group mappings |
| **poweruser** | 3 | Ad-hoc session creation + address book connect |
| **operator** | 2 | Address book connect only (no ad-hoc sessions) |
| **viewer** | 1 | Read-only — view sessions and recordings |

Roles are hierarchical: each role includes all permissions of lower roles. For example, a poweruser can do everything an operator can, plus create ad-hoc sessions.

## Authentication paths

### API key admins

API key holders always have full **admin** access (level 4). There is no way to restrict an API key to a lower role. API keys are intended for automation, CI/CD, and system administration.

```bash
# Create an API key admin
rustguac add-admin --name automation

# With IP restrictions and expiry
rustguac add-admin --name ci-bot \
  --allowed-ips "10.0.0.0/8,192.168.1.0/24" \
  --expires "2026-12-31T00:00:00Z"
```

### OIDC users

OIDC users are assigned a role through three mechanisms (in order of precedence):

1. **Group-to-role mappings** — evaluated on every OIDC login. If the user's OIDC groups match any mappings, the highest matching role is applied.
2. **Manual role assignment** — admins can set a user's role via CLI, API, or the Admin page.
3. **Default role** — new users get the `default_role` from OIDC config on first login (default: `operator`).

## Endpoint access control

### Session management

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `POST /api/sessions` | poweruser | Create ad-hoc sessions |
| `GET /api/sessions` | operator | List all sessions |
| `GET /api/sessions/:id` | operator | View session details |
| `DELETE /api/sessions/:id` | operator | Non-admins can only delete their own sessions |

### Address book

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `GET /api/addressbook/folders` | operator | Filtered by OIDC group membership |
| `GET /api/addressbook/folders/:scope/:folder/entries` | operator | Requires folder group access |
| `POST .../entries/:entry/connect` | operator | Creates session from address book entry |
| `POST /api/addressbook/folders` | admin | Create folders |
| `PUT /api/addressbook/folders/:scope/:folder` | admin | Update folder config |
| `DELETE /api/addressbook/folders/:scope/:folder` | admin | Delete folders |
| `POST .../entries` | admin | Create entries |
| `PUT .../entries/:entry` | admin | Update entries |
| `DELETE .../entries/:entry` | admin | Delete entries |

### Recordings

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `GET /api/recordings` | operator | List recordings |
| `GET /api/recordings/:name` | operator | Download/play recording |
| `DELETE /api/recordings/:name` | admin | Delete recording |

### User management

| Endpoint | Required role |
|----------|--------------|
| `GET /api/users` | admin |
| `PUT /api/users/:email/role` | admin |
| `DELETE /api/users/:email` | admin |
| `POST /api/users/:email/disable` | admin |
| `POST /api/users/:email/enable` | admin |
| `DELETE /api/users/:email/sessions` | admin |

### Group-to-role mappings

| Endpoint | Required role |
|----------|--------------|
| `GET /api/admin/group-mappings` | admin |
| `POST /api/admin/group-mappings` | admin |
| `PUT /api/admin/group-mappings/:id` | admin |
| `DELETE /api/admin/group-mappings/:id` | admin |

### Public endpoints

| Endpoint | Auth required | Notes |
|----------|--------------|-------|
| `GET /api/health` | None | Always returns 200 |
| `GET /api/auth/status` | None | Returns OIDC enabled status |
| `GET /api/me` | Any authenticated | Returns current user info |

## Folder access control

Address book folders have group-based access control. Each folder has an `allowed_groups` list stored in its `.config` entry in Vault.

- **Admins** bypass group checks and see all folders
- **Operators and powerusers** see only folders where their OIDC groups intersect with the folder's `allowed_groups`
- If `allowed_groups` is empty, all authenticated users can see the folder

### Example

A folder with `allowed_groups: ["engineering", "devops"]`:
- A user with OIDC groups `["engineering", "marketing"]` **can** access it (engineering matches)
- A user with OIDC groups `["marketing", "sales"]` **cannot** access it (no match)
- An admin **can** always access it regardless of groups

## Group-to-role mappings

Admins can configure automatic role assignment based on OIDC group membership. This is managed in the Admin page or via the API.

### How it works

1. When a user logs in via OIDC, their group memberships are extracted from the JWT
2. Each group is checked against the `group_role_mappings` table
3. If any groups match, the **highest role** among all matches is applied
4. If no groups match, the user's existing role is preserved

### Example

| OIDC Group | Mapped Role |
|-----------|-------------|
| `sysadmin` | admin |
| `engineering` | poweruser |
| `support` | operator |

A user with groups `["engineering", "support"]` would get `poweruser` (the higher of the two matching roles).

## User management CLI

```bash
# List all OIDC users
rustguac list-users

# Set a user's role
rustguac set-role --email user@example.com --role poweruser

# Disable a user (blocks login)
rustguac disable-user --email user@example.com

# Re-enable a user
rustguac enable-user --email user@example.com

# Delete a user
rustguac delete-user --email user@example.com
```

## Admin (API key) management CLI

```bash
# Create an admin
rustguac add-admin --name myadmin

# With IP restrictions
rustguac add-admin --name myadmin --allowed-ips "10.0.0.0/8,192.168.1.0/24"

# With expiry
rustguac add-admin --name myadmin --expires "2026-12-31T00:00:00Z"

# List admins
rustguac list-admins

# Disable/enable
rustguac disable-admin --name myadmin
rustguac enable-admin --name myadmin

# Rotate key (generates new key, invalidates old immediately)
rustguac rotate-key --name myadmin

# Delete
rustguac delete-admin --name myadmin
```

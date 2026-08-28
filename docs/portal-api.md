# Frontend brief: passkey portal (role model)

Access control is an Azure-style **role model with two scopes**. The auth ceremony
(`request-verification → verify → make-credential-options → make-credential`,
`assertion-options → make-assertion`, `refresh`) and DPoP token handling are unchanged.

**All JSON is camelCase** (request and response). WebAuthn ceremony payloads keep their spec field
names. Authenticated calls use `Authorization: DPoP <accessToken>` + the `DPoP: <proof>` header,
sent from the management/portal origin.

## Scopes

- **Installation (platform)** — a `SuperTenantAdmin` (on the JWT `platformRoles` claim) can see and
  manage every tenant.
- **Tenant** — within a tenant a user holds `TenantAdmin` / `UserAdmin` / `Member`, surfaced as
  `myRole`. `OwnerUserId` is audit-only and no longer drives access.

## 1. `GET /users/me`

```json
{
  "user": { "id": "...", "username": "...", "displayName": "..." },
  "permissions": ["tenants:manage"],
  "platformRoles": ["SuperTenantAdmin"]
}
```

`platformRoles` is empty for non-platform users.

## 2. Tenants

| Method | Path | Notes |
|---|---|---|
| GET | `/tenants` | Tenants where the caller has a real tenant role (`TenantAdmin`/`UserAdmin`/`Member`). A portal user's `customer`-role identity in the management tenant is **not** a membership and is filtered out — so the management tenant only appears here for users who actually have a role in it. |
| GET | `/tenants?scope=all` | **All** tenants in the installation, including the management tenant. `SuperTenantAdmin` only, else 403. |
| GET | `/tenants/{id}` | Single tenant; includes `myRole`. 404 if not a member and not platform admin. |
| POST | `/tenants` | Create. Requires `tenants:manage` **or** `SuperTenantAdmin`. Creator becomes `TenantAdmin`. |
| PUT | `/tenants/{id}` | Update settings — `TenantAdmin` or platform admin. |
| POST | `/tenants/{id}/rotate-key` · `/cleanup-keys` · `/revoke-sessions` | `TenantAdmin` or platform admin. |

Tenant DTO (camelCase): `id`, `serverName`, `isManagementTenant`, `myRole`
(`"TenantAdmin"`|`"UserAdmin"`|`"Member"`|`""`), `admins` (display names of the tenant's
TenantAdmins), `ownerDisplayName`, `ownerUsername` (fallback for the Admins column), plus the
usual settings fields (`allowedOrigins`, `jwtIssuer`, `registrationMode`, …).

## 3. Users & roles inside a tenant

Authorized by the caller's role in that tenant (or platform admin). Reads need `UserAdmin`;
deletes / role changes / session revocation need `TenantAdmin`.

| Method | Path | Min role | Returns |
|---|---|---|---|
| GET | `/tenants/{t}/users` · `/users/{id}` | UserAdmin | user(s) |
| POST | `/tenants/{t}/users` | UserAdmin | user (invite/pre-create) |
| PUT | `/tenants/{t}/users/{id}` | UserAdmin | user |
| DELETE | `/tenants/{t}/users/{id}` | TenantAdmin | 204 |
| PATCH | `/tenants/{t}/users/{id}/roles` | TenantAdmin | `{ userId, roles, permissions }` |
| POST/DELETE | `/tenants/{t}/users/{id}/roles/{roleName}` | TenantAdmin | `{ userId, roles, permissions }` |
| POST | `/tenants/{t}/users/{id}/revoke-sessions` | TenantAdmin | `{ message }` |
| GET | `/tenants/{t}/roles` · `/roles/{id}` | UserAdmin | role(s) |
| POST/PUT/DELETE | `/tenants/{t}/roles[/{id}]` | TenantAdmin | role / 204 |

**"Give admin rights"** = grant the `TenantAdmin` role: `POST /tenants/{t}/users/{id}/roles/TenantAdmin`
(role names are case-insensitive; legacy `admin` aliases to TenantAdmin). Built-in roles
(`TenantAdmin` / `UserAdmin` / `Member`) are seeded into every tenant.

## 4. Platform admins — `SuperTenantAdmin` only

```
GET    /admin/super-admins        → [ { "id": "...", "username": "...", "displayName": "..." } ]
POST   /admin/super-admins        ← { "username": "jane@example.com" }
DELETE /admin/super-admins/{id}
```

403 for non-platform-admins. The target of POST must be an existing portal (management-tenant) user.

## Rules

- **404, not 403,** for a tenant you have no membership in and no platform role (existence hidden).
  A member lacking the required tier gets 403.
- **Usernames are lower-cased** server-side; lowercase before sending, compare case-insensitively.
- The first installation owner and the management-tenant owner are auto-granted `SuperTenantAdmin`.

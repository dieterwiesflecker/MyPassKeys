# RBAC, Groups & Authorization

## Roles & permissions

Authorization is **purely membership-based** — there is no `OwnerUserId` field, no platform-admin tier, and no cross-tenant power. Each tenant has a role catalog (`TenantRole` documents) managed via `RoleEndpoints` (`/roles`). Each role has a normalized, tenant-unique `Name` (immutable after creation), `DisplayName`, `Description`, and a `Permissions` list. `Fido2AppUser.Roles` stores role *names*; user-role assignment endpoints (`UserEndpoints`: `PATCH /users/{id}/roles`, `POST`/`DELETE /users/{id}/roles/{roleName}`) validate names against the catalog. `TokenService.GenerateTokenAsync` emits one `role` claim per role plus one `permissions` claim per permission (union across the user's roles). Deleting a role cascades — it is stripped from every user that holds it.

### Built-in roles (seeded into every tenant — see `TenantRoleModel.BuiltInRoles()`)

- **`tenantadmin`** — full administration of the tenant. Carries `users:*`, `roles:*`, `groups:*`, `tenant:settings:*`, and the back-compat `roles:manage` permission.
- **`useradmin`** — manage users and the role catalog. Carries `users:read` + `users:write` + `users:delete` + `roles:read` + `roles:write` + `roles:delete` + `groups:read`. It does **not** carry `roles:manage`. A useradmin can create/edit/**delete** users and create/edit/delete catalog roles, and can assign/revoke roles to users — but everywhere it is bounded by escalation guards: it cannot create/modify a role carrying a permission it doesn't itself hold (so it can't mint an admin role), cannot modify/delete an admin-equivalent role, cannot grant/revoke `tenantadmin` (or any `roles:manage` role), and cannot delete a user who holds one.
- **`groupadmin`** — manage the tenant's groups and group membership. Carries `groups:read` + `groups:write` + `groups:delete` + `groups:members` plus read-only `users:read` + `roles:read` (to pick members and roles). Does **not** carry `roles:manage` — bounded by the privileged-group guards.
- **`app`** — baseline app member. Carries `users:read` + `roles:read` + `groups:read` only (no write/admin). Assign it to ordinary end users who should be able to **list** the tenant's users, roles and groups without any admin power.

**Access helpers**: `TenantRoleModel.IsTenantAdmin(roles)`, `IsUserAdminOrAbove(roles)`, and `MyRole(roles)` (returns `"TenantAdmin"`, `"UserAdmin"`, `"GroupAdmin"`, `"App"`, or `""`). Custom roles with custom permissions can be added per tenant via `POST /roles`; only tenantadmin/useradmin are referenced by the membership-tier checks.

**"My tenants"** (`GET /tenants`) returns only the tenants where the caller is a `tenantadmin` or `useradmin` member. End users registering passkeys against a customer RP carry no role at all — their tokens have no `role`/`permissions` claims, and they don't see the portal.

## Groups (AD-style)

Each tenant has a group catalog (`TenantGroup` documents, `GroupEndpoints` under `/groups`). A group has a normalized, tenant-unique, immutable `Name`, `DisplayName`, `Description`, user members (`MemberUserIds`), **nested group members** (`MemberGroupIds`), and attached catalog role names (`Roles`). Semantics: a member of group A, where A is a member of group B, is transitively a member of B and inherits the roles of **both** — `TokenService.GenerateTokenAsync` unions group-derived roles into the `roles`/`scp` claims and emits one `groups` claim per effective group name. Members are managed via `POST`/`DELETE /groups/{id}/members/users/{userId}` and `/groups/{id}/members/groups/{childGroupId}` (never via group create/update bodies).

### Recursion & cycles

All graph logic is in the pure static `TenantGroupModel` (traversals carry visited sets, so a stored cycle degrades to a no-op): `GroupsForUser` (direct + ancestors), `IsUserMember` (recursive check, exposed as `GET /groups/{id}/is-member/{userId}` → `{isMember, isDirectMember}`), `DescendantGroups`/`RecursiveMemberUserIds` (power `GET /groups/{id}/members?recursive=true`), `EffectiveRoleNames` (group's own + ancestor roles), and `WouldCreateCycle` — nesting that would create a cycle (including self-membership) is rejected with 400 at `POST /groups/{id}/members/groups/{childId}`. Recursion is resolved **in memory** over `GetGroupsAsync()` (tenants are small); don't rewrite it as per-node DB queries. `GET /users/{id}/groups` lists a user's groups (`?recursive=false` for direct only).

### Gates

Reads are directory reads (any authenticated member, like `/users` and `/roles`). Catalog writes gate on `groups:write`/`groups:delete`; membership writes on `groups:members`.

**Escalation guards** (bypassed by `roles:manage`): because membership confers roles, a non-`roles:manage` caller (a) may not attach/detach a privileged (`roles:manage`-carrying) role on a group, and (b) may not modify, delete, or change the membership of a group whose **effective** role set (own + inherited from ancestor groups) contains a privileged role — otherwise adding yourself to an admin group would be a straight escalation. Do not weaken these to direct-roles-only checks.

### Cascades

Role delete strips the role from all groups (`RemoveRoleFromAllGroupsAsync` / `...ForTenantAsync`, wired in both `RoleEndpoints` and `PortalEndpoints`); user delete strips the user from all groups' `MemberUserIds`; group delete unlinks it from every nesting group; tenant delete removes all its groups.

### Responses

`Roles` fields on user endpoints stay **direct-only** (the editable state — a frontend PATCHing them back must not persist group-derived roles), while the `Permissions` in `/users/me` and `UserRolesResponse` are resolved from the **effective** role set (direct + group-derived) so they match what tokens carry. Like role claims, freshly changed group membership only takes effect on the member's next token issuance.

## Authorization gates

All authorization checks live in three helpers, none of them owner-based:

- **User create/edit** (`POST`/`PUT /users`) go through `AuthorizeRoleAssignerAsync` (`roles:manage` **or** `users:write`) — so a **useradmin** can create and edit users, which is its whole purpose. The `Roles` field on these endpoints is subject to the same `GuardPrivilegedRoleChangeAsync` escalation guard: a non-`roles:manage` caller cannot set/keep-out a privileged role, so a useradmin can't mint (or demote) a tenantadmin via user create/edit.
- **User delete** (`DELETE /users/{id}`) gates on `users:delete` (tenantadmin and useradmin both carry it). Guard: a caller **without `roles:manage`** cannot delete a user who holds a privileged (tenantadmin-equivalent) role, and no one can delete their own account.
- **Role-catalog writes** gate per-verb: `POST`/`PUT /roles` on `roles:write`, `DELETE /roles/{id}` on `roles:delete` (tenantadmin and useradmin carry all three). `RoleEndpoints.GuardRoleWrite` enforces two escalation limits on a caller **without `roles:manage`**: (a) it may not create or modify a role whose resulting permission set contains any permission the caller does not itself hold (blocks minting `roles:manage`/`tenant:settings:*` roles — "you can't grant what you don't have"); and (b) it may not modify or delete a role that already carries `roles:manage`. This is why `roles:write` is safe to hand to useradmin. Reads (`GET /roles`, `GET /roles/{id}`) gate on `roles:read`.
- `UserEndpoints.AuthorizePermissionAsync(principal, tenantService, permission)` — the generic gate: resolves the tenant and checks the caller's token carries `permission` (read from the space-delimited `scp` claim). `AuthorizeRoleManagerAsync` is a thin wrapper over it for `roles:manage`.
- **Read gates** (`AuthorizePermissionAsync`): `GET /users` and `GET /users/{id}` require `users:read`; `GET /roles` and `GET /roles/{id}` require `roles:read`. These are the read permissions carried by `useradmin` and `app` (and `tenantadmin`), so ordinary members with the `app` role can list users/roles. **Do not gate reads on `roles:manage`** — that was the old behavior and it wrongly locked out `useradmin`/`app` despite them holding the read permission.
- **Role-assignment gate** (`UserEndpoints.AuthorizeRoleAssignerAsync`): `PATCH /users/{id}/roles`, `POST`/`DELETE /users/{id}/roles/{roleName}` accept a caller holding **either `roles:manage` (tenantadmin) or `users:write` (useradmin)** — so a useradmin can grant/revoke roles. But a caller **without `roles:manage`** is subject to a **privilege-escalation guard** (`GuardPrivilegedRoleChangeAsync`): they may not grant *or* revoke any **privileged role** — one whose permission set carries `roles:manage` (the built-in `tenantadmin` or any custom admin-equivalent). This stops a useradmin from promoting a user (or themselves) to admin. `GET /users/{id}/roles` is a read, gated on `users:read`. Do not "simplify" the assignment endpoints back to a plain `roles:manage` check — that both re-locks-out useradmin and drops the escalation guard.
- `AuthorizeRoleManagerAsync` (= `roles:manage`) — now gates only `POST /users/{id}/revoke-sessions`. It is also the **capability boundary** the escalation guards check against (`UserEndpoints.HasRoleManage`): holding `roles:manage` bypasses every guard above. The built-in `tenantadmin` role carries it implicitly; custom roles may carry it to delegate full role/admin authority. **`roles:manage` is a superset capability, not a per-endpoint gate for `/roles` writes anymore** — those moved to `roles:write` + guards.
- `TenantEndpoints.LookupAsync` + `RequireTenantAdmin(tenant, membership)` — used by `PUT /tenants/{id}`, `/rotate-key`, `/cleanup-keys`, `/revoke-sessions`. Non-members get 404 (existence hidden); useradmin-only members get 403. `GET /tenants/{id}` requires at least useradmin membership.
- `PortalEndpoints.AuthorizeTenantAsync(..., bool tenantAdminRequired)` — same membership semantics for cross-tenant management calls from the management origin (`/tenants/{tenantId}/users`, `/tenants/{tenantId}/roles`).
- **Permission-claim freshness**: because `roles:manage` is read from the access token, a freshly granted or revoked permission only takes effect on the holder's next token issuance.

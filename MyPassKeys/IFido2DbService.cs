namespace MyPassKeys;

public interface IFido2DbService
{
  Task<Fido2AppUser?> GetUserByUsernameAsync(string username);
  Task<Fido2AppUser?> GetUserByIdAsync(Guid userId);
  Task UpsertUserAsync(Fido2AppUser user);
  Task<List<Fido2StoredCredential>> GetCredentialsByUserIdAsync(Guid userId);
  Task<Fido2StoredCredential?> GetCredentialByIdAsync(byte[] credentialId);
  Task<Fido2StoredCredential?> GetCredentialByIdAsync(string credentialId);
  Task UpsertCredentialAsync(Fido2StoredCredential credential);

  // --- Trusted cross-tenant credentials (Tenant.TrustedCredentialTenantIds) ---
  /// <summary>
  /// Looks up a credential across the supplied tenants, bypassing current-tenant scoping.
  /// Used by make-assertion when the current tenant trusts other same-domain tenants'
  /// credentials; callers must pass the current tenant's TrustedCredentialTenantIds only.
  /// </summary>
  Task<Fido2StoredCredential?> GetCredentialByIdForTenantsAsync(string credentialId, IReadOnlyCollection<Guid> tenantIds);
  Task<List<Fido2StoredCredential>> GetCredentialsByUserIdForTenantAsync(Guid tenantId, Guid userId);
  /// <summary>
  /// Upserts a credential against the supplied <paramref name="tenantId"/> instead of the
  /// current tenant. Counter updates on a trusted tenant's credential MUST use this — the
  /// current-tenant variant would silently re-home the credential to the requesting tenant.
  /// </summary>
  Task UpsertCredentialForTenantAsync(Guid tenantId, Fido2StoredCredential credential);
  Task StoreChallengeAsync(string username, string challenge);
  Task<string?> GetChallengeAsync(string username);
  Task<Tenant?> GetTenantByHostAsync(string? host);
  /// <summary>
  /// Returns ALL tenants that list <paramref name="origin"/> in their AllowedOrigins. More than
  /// one is legitimate (path-separated apps sharing a domain) — the caller disambiguates with
  /// X-Tenant-ID, so resolution must surface the ambiguity rather than silently pick one.
  /// </summary>
  Task<List<Tenant>> GetTenantsByOriginAsync(string? origin);
  Task<Tenant?> GetManagementTenantAsync();
  Task<Tenant?> GetTenantByIdAsync(Guid tenantId);
  Task<Tenant?> GetTenantByServerNameAsync(string serverName);
  Task<Tenant?> GetTenantByIssuerAsync(string issuer);
  Task<Fido2RefreshToken?> GetRefreshTokenAsync(string token);
  Task UpsertRefreshTokenAsync(Fido2RefreshToken token);
  Task RevokeUserRefreshTokensAsync(Guid userId);
  Task UpsertTenantAsync(Tenant tenant);
  /// <summary>
  /// Permanently deletes a tenant and ALL of its scoped data — its users, their stored
  /// credentials and refresh tokens, and its role catalog. Irreversible. The management tenant
  /// must never be passed here (the endpoint guards against it).
  /// </summary>
  Task DeleteTenantAsync(Guid tenantId);
  Task<List<Tenant>> GetAllTenantsAsync();
  Task<List<Fido2AppUser>> GetUsersAsync();
  Task DeleteUserAsync(Guid userId);

  // --- Portal (cross-tenant) user access ---
  // Explicit-tenantId variants used by PortalEndpoints, which operate on a tenant the request
  // is NOT currently scoped to (the caller is on the management origin). They bypass the
  // request's current-tenant resolution; the caller is responsible for authorizing access.
  Task<List<Fido2AppUser>> GetUsersForTenantAsync(Guid tenantId);
  Task<Fido2AppUser?> GetUserByIdForTenantAsync(Guid tenantId, Guid userId);
  Task<Fido2AppUser?> GetUserByUsernameForTenantAsync(Guid tenantId, string username);
  Task UpsertUserForTenantAsync(Guid tenantId, Fido2AppUser user);
  Task DeleteUserForTenantAsync(Guid tenantId, Guid userId);

  // --- Membership (cross-tenant) ---
  // A user's tenant memberships are represented by their per-tenant Fido2AppUser records, linked
  // across tenants by Username (email). These power "my tenants" and the tenant list.
  Task<List<Fido2AppUser>> GetMembershipsByUsernameAsync(string username);
  Task<List<Tenant>> GetTenantsByIdsAsync(IEnumerable<Guid> tenantIds);

  // --- Roles ---
  Task<List<TenantRole>> GetRolesAsync();
  Task<TenantRole?> GetRoleByIdAsync(Guid roleId);
  Task<TenantRole?> GetRoleByNameAsync(string name);
  Task UpsertRoleAsync(TenantRole role);
  /// <summary>
  /// Upserts a role against the supplied <paramref name="tenantId"/>, bypassing the request's
  /// current-tenant resolution. Used by bootstrap and <c>POST /tenants</c> to seed default roles
  /// on a tenant the caller is not currently scoped to.
  /// </summary>
  Task UpsertRoleForTenantAsync(Guid tenantId, TenantRole role);
  Task DeleteRoleAsync(Guid roleId);
  Task RemoveRoleFromAllUsersAsync(string roleName);

  // --- Portal (cross-tenant) role access --- see note above on the user variants.
  Task<List<TenantRole>> GetRolesForTenantAsync(Guid tenantId);
  Task<TenantRole?> GetRoleByIdForTenantAsync(Guid tenantId, Guid roleId);
  Task<TenantRole?> GetRoleByNameForTenantAsync(Guid tenantId, string name);
  Task DeleteRoleForTenantAsync(Guid tenantId, Guid roleId);
  Task RemoveRoleFromAllUsersForTenantAsync(Guid tenantId, string roleName);

  // --- Groups ---
  // AD-style groups: users and nested groups as members, plus attached role names members inherit
  // (see TenantGroup / TenantGroupModel). Recursive membership is resolved in memory over the
  // tenant's full group list — tenants are small, so callers use GetGroupsAsync + TenantGroupModel.
  Task<List<TenantGroup>> GetGroupsAsync();
  Task<TenantGroup?> GetGroupByIdAsync(Guid groupId);
  Task<TenantGroup?> GetGroupByNameAsync(string name);
  Task UpsertGroupAsync(TenantGroup group);
  /// <summary>
  /// Deletes a group and unlinks it from every group that lists it as a nested member.
  /// </summary>
  Task DeleteGroupAsync(Guid groupId);
  Task RemoveRoleFromAllGroupsAsync(string roleName);
  Task RemoveRoleFromAllGroupsForTenantAsync(Guid tenantId, string roleName);

  // --- Portal (cross-tenant) group access --- see note above on the user variants.
  Task<List<TenantGroup>> GetGroupsForTenantAsync(Guid tenantId);
  Task<TenantGroup?> GetGroupByIdForTenantAsync(Guid tenantId, Guid groupId);
  Task<TenantGroup?> GetGroupByNameForTenantAsync(Guid tenantId, string name);
  Task UpsertGroupForTenantAsync(Guid tenantId, TenantGroup group);
  /// <summary>Deletes a group and unlinks it from every nesting group — cross-tenant variant.</summary>
  Task DeleteGroupForTenantAsync(Guid tenantId, Guid groupId);

  // --- Sessions ---
  Task RevokeAllRefreshTokensAsync(Guid tenantId);
  Task RevokeUserRefreshTokensForTenantAsync(Guid tenantId, Guid userId);
}
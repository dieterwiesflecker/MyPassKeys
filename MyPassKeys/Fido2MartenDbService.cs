using Marten;
using StackExchange.Redis;

namespace MyPassKeys;

/// <summary>
/// Marten-backed document store. ALL reads and writes of security-critical documents
/// (Tenant, Fido2AppUser, Fido2StoredCredential, TenantRole, TenantGroup, Fido2RefreshToken)
/// flow through this class, which is what makes the integrity layer airtight: every write is
/// sealed via <see cref="IDocumentIntegrity"/> (bumping the document's Version) and anchored
/// via <see cref="IVersionAnchor"/> after the save; every read verifies the seal AND the
/// version anchor — a document altered OR rolled back by a direct database write fails and the
/// request dies with <see cref="DocumentTamperedException"/>. When adding a method here, keep
/// that invariant: seal before Store, record anchors after SaveChanges, verify loaded documents
/// BEFORE mutating and re-sealing them (re-sealing unverified data would bless tampering).
/// </summary>
public class Fido2MartenDbService(
  IDocumentSession session,
  IConnectionMultiplexer redis,
  ITenantService tenantService,
  IDocumentIntegrity integrity,
  IVersionAnchor anchors
) : IFido2DbService
{
  private async Task<Tenant> RequireTenantAsync()
  {
    var tenant = await tenantService.GetCurrentTenantAsync();
    if (tenant == null)
      throw new InvalidOperationException("The current request does not map to a known tenant.");
    return tenant;
  }

  /// <summary>Verifies a loaded document's integrity seal and version anchor (null passes through).</summary>
  private async Task<T?> VerifiedAsync<T>(T? doc) where T : class
  {
    if (doc == null) return null;
    integrity.Verify(doc);
    await anchors.CheckAsync(doc);
    return doc;
  }

  /// <summary>Verifies every element of a loaded list.</summary>
  private async Task<List<T>> VerifiedAsync<T>(IReadOnlyList<T> docs) where T : class
  {
    foreach (var doc in docs)
    {
      integrity.Verify(doc);
      await anchors.CheckAsync(doc);
    }
    return (List<T>)docs;
  }

  public async Task<Fido2AppUser?> GetUserByUsernameAsync(string username)
  {
    var tenant = await RequireTenantAsync();
    var normalized = username.NormalizeUsername();
    return await VerifiedAsync(await session.Query<Fido2AppUser>().FirstOrDefaultAsync(u => u.Username == normalized && u.TenantId == tenant.Id));
  }

  public async Task<Fido2AppUser?> GetUserByIdAsync(Guid userId)
  {
    var tenant = await RequireTenantAsync();
    return await VerifiedAsync(await session.Query<Fido2AppUser>().FirstOrDefaultAsync(u => u.Id == userId && u.TenantId == tenant.Id));
  }

  public async Task UpsertUserAsync(Fido2AppUser user)
  {
    var tenant = await RequireTenantAsync();
    user.TenantId = tenant.Id;
    integrity.Seal(user);
    session.Store(user);
    await session.SaveChangesAsync();
    await anchors.RecordAsync(user);
  }

  public async Task<List<Fido2StoredCredential>> GetCredentialsByUserIdAsync(Guid userId)
  {
    var tenant = await RequireTenantAsync();
    return await VerifiedAsync(await session.Query<Fido2StoredCredential>().Where(c => c.UserId == userId && c.TenantId == tenant.Id).ToListAsync());
  }

  public async Task<Fido2StoredCredential?> GetCredentialByIdAsync(byte[] credentialId)
  {
    var idString = credentialId.ToBase64Url();
    return await GetCredentialByIdAsync(idString);
  }

  public async Task<Fido2StoredCredential?> GetCredentialByIdAsync(string credentialId)
  {
    var tenant = await RequireTenantAsync();
    // IMPORTANT: LoadAsync is not tenant-aware. We must use a query to ensure
    // we only retrieve a credential belonging to the current tenant.
    return await VerifiedAsync(await session.Query<Fido2StoredCredential>()
      .FirstOrDefaultAsync(c => c.Id == credentialId && c.TenantId == tenant.Id));
  }

  public async Task UpsertCredentialAsync(Fido2StoredCredential credential)
  {
    var tenant = await RequireTenantAsync();
    credential.TenantId = tenant.Id;
    integrity.Seal(credential);
    session.Store(credential);
    await session.SaveChangesAsync();
    await anchors.RecordAsync(credential);
  }

  public async Task<Fido2StoredCredential?> GetCredentialByIdForTenantsAsync(string credentialId, IReadOnlyCollection<Guid> tenantIds)
  {
    if (tenantIds.Count == 0) return null;
    return await VerifiedAsync(await session.Query<Fido2StoredCredential>()
      .FirstOrDefaultAsync(c => c.Id == credentialId && tenantIds.Contains(c.TenantId)));
  }

  public async Task<List<Fido2StoredCredential>> GetCredentialsByUserIdForTenantAsync(Guid tenantId, Guid userId)
  {
    return await VerifiedAsync(await session.Query<Fido2StoredCredential>()
      .Where(c => c.UserId == userId && c.TenantId == tenantId).ToListAsync());
  }

  public async Task UpsertCredentialForTenantAsync(Guid tenantId, Fido2StoredCredential credential)
  {
    credential.TenantId = tenantId;
    integrity.Seal(credential);
    session.Store(credential);
    await session.SaveChangesAsync();
    await anchors.RecordAsync(credential);
  }

  public async Task StoreChallengeAsync(string username, string challenge)
  {
    var tenant = await RequireTenantAsync();
    var db = redis.GetDatabase();
    await db.StringSetAsync($"Challenge:{tenant.Id}:{username.NormalizeUsername()}", challenge, TimeSpan.FromMinutes(3));
  }

  public async Task<string?> GetChallengeAsync(string username)
  {
    var tenant = await RequireTenantAsync();
    var db = redis.GetDatabase();
    var value = await db.StringGetDeleteAsync($"Challenge:{tenant.Id}:{username.NormalizeUsername()}");
    return value.HasValue ? value.ToString() : null;
  }

  public async Task<Tenant?> GetTenantByHostAsync(string? host)
  {
    if (string.IsNullOrEmpty(host)) return null;
    var normalizedHost = host.ToLowerInvariant();
    return await VerifiedAsync(await session.Query<Tenant>().FirstOrDefaultAsync(t => t.Hosts.Contains(normalizedHost)));
  }

  public async Task<List<Tenant>> GetTenantsByOriginAsync(string? origin)
  {
    if (string.IsNullOrEmpty(origin)) return [];
    var normalizedOrigin = origin.TrimEnd('/');
    return await VerifiedAsync(await session.Query<Tenant>()
      .Where(t => t.AllowedOrigins.Contains(normalizedOrigin))
      .ToListAsync());
  }

  public async Task<Tenant?> GetManagementTenantAsync()
  {
    return await VerifiedAsync(await session.Query<Tenant>().FirstOrDefaultAsync(t => t.IsManagementTenant));
  }

  public async Task<Tenant?> GetTenantByIdAsync(Guid tenantId)
  {
    return await VerifiedAsync(await session.LoadAsync<Tenant>(tenantId));
  }

  public async Task<Tenant?> GetTenantByServerNameAsync(string serverName)
  {
    var normalized = serverName.Trim().ToLower();
    return await VerifiedAsync(await session.Query<Tenant>()
        .FirstOrDefaultAsync(t => t.ServerName.ToLower() == normalized));
  }

  public async Task<Tenant?> GetTenantByIssuerAsync(string issuer)
  {
    if (string.IsNullOrEmpty(issuer)) return null;
    return await VerifiedAsync(await session.Query<Tenant>().FirstOrDefaultAsync(t => t.JwtIssuer == issuer));
  }

  public async Task<Fido2RefreshToken?> GetRefreshTokenAsync(string token)
  {
    var tenant = await RequireTenantAsync();
    return await VerifiedAsync(await session.Query<Fido2RefreshToken>()
        .FirstOrDefaultAsync(t => t.Token == token && t.TenantId == tenant.Id));
  }

  public async Task UpsertRefreshTokenAsync(Fido2RefreshToken token)
  {
    var tenant = await RequireTenantAsync();
    token.TenantId = tenant.Id;
    integrity.Seal(token);
    session.Store(token);
    await session.SaveChangesAsync();
    await anchors.RecordAsync(token);
  }

  public async Task RevokeUserRefreshTokensAsync(Guid userId)
  {
    var tenant = await RequireTenantAsync();
    await RevokeUserRefreshTokensForTenantAsync(tenant.Id, userId);
  }

  public async Task UpsertTenantAsync(Tenant tenant)
  {
      integrity.Seal(tenant);
      session.Store(tenant);
      await session.SaveChangesAsync();
      await anchors.RecordAsync(tenant);
  }

  public async Task DeleteTenantAsync(Guid tenantId)
  {
      // Cascade: remove every document scoped to this tenant, then the tenant itself.
      // Version anchors of deleted documents are left behind on purpose — ids are never
      // reused, so they are inert, and removing them would require loading every id first.
      session.DeleteWhere<Fido2StoredCredential>(c => c.TenantId == tenantId);
      session.DeleteWhere<Fido2RefreshToken>(t => t.TenantId == tenantId);
      session.DeleteWhere<Fido2AppUser>(u => u.TenantId == tenantId);
      session.DeleteWhere<TenantRole>(r => r.TenantId == tenantId);
      session.DeleteWhere<TenantGroup>(g => g.TenantId == tenantId);
      session.DeleteWhere<Tenant>(t => t.Id == tenantId);
      await session.SaveChangesAsync();
  }

  public async Task<List<Tenant>> GetAllTenantsAsync()
  {
      return await VerifiedAsync(await session.Query<Tenant>().ToListAsync());
  }

  public async Task<List<Fido2AppUser>> GetUsersAsync()
  {
      var tenant = await RequireTenantAsync();
      return await VerifiedAsync(await session.Query<Fido2AppUser>().Where(u => u.TenantId == tenant.Id).ToListAsync());
  }

  public async Task DeleteUserAsync(Guid userId)
  {
      var tenant = await RequireTenantAsync();
      session.DeleteWhere<Fido2StoredCredential>(c => c.UserId == userId && c.TenantId == tenant.Id);
      session.DeleteWhere<Fido2RefreshToken>(t => t.UserId == userId && t.TenantId == tenant.Id);
      session.DeleteWhere<Fido2AppUser>(u => u.Id == userId && u.TenantId == tenant.Id);
      var touchedGroups = await RemoveUserFromGroupsAsync(tenant.Id, userId);
      await session.SaveChangesAsync();
      foreach (var group in touchedGroups) await anchors.RecordAsync(group);
  }

  public async Task<List<Fido2AppUser>> GetUsersForTenantAsync(Guid tenantId)
  {
      return await VerifiedAsync(await session.Query<Fido2AppUser>()
          .Where(u => u.TenantId == tenantId).ToListAsync());
  }

  public async Task<Fido2AppUser?> GetUserByIdForTenantAsync(Guid tenantId, Guid userId)
  {
      return await VerifiedAsync(await session.Query<Fido2AppUser>()
          .FirstOrDefaultAsync(u => u.Id == userId && u.TenantId == tenantId));
  }

  public async Task<Fido2AppUser?> GetUserByUsernameForTenantAsync(Guid tenantId, string username)
  {
      var normalized = username.NormalizeUsername();
      return await VerifiedAsync(await session.Query<Fido2AppUser>()
          .FirstOrDefaultAsync(u => u.Username == normalized && u.TenantId == tenantId));
  }

  public async Task UpsertUserForTenantAsync(Guid tenantId, Fido2AppUser user)
  {
      user.TenantId = tenantId;
      integrity.Seal(user);
      session.Store(user);
      await session.SaveChangesAsync();
      await anchors.RecordAsync(user);
  }

  public async Task DeleteUserForTenantAsync(Guid tenantId, Guid userId)
  {
      session.DeleteWhere<Fido2StoredCredential>(c => c.UserId == userId && c.TenantId == tenantId);
      session.DeleteWhere<Fido2RefreshToken>(t => t.UserId == userId && t.TenantId == tenantId);
      session.DeleteWhere<Fido2AppUser>(u => u.Id == userId && u.TenantId == tenantId);
      var touchedGroups = await RemoveUserFromGroupsAsync(tenantId, userId);
      await session.SaveChangesAsync();
      foreach (var group in touchedGroups) await anchors.RecordAsync(group);
  }

  /// <summary>Stages removal of a deleted user from every group that lists them (no save).
  /// Returns the re-sealed groups so the caller can record their anchors after saving.</summary>
  private async Task<List<TenantGroup>> RemoveUserFromGroupsAsync(Guid tenantId, Guid userId)
  {
      var groups = await VerifiedAsync(await session.Query<TenantGroup>()
          .Where(g => g.TenantId == tenantId && g.MemberUserIds.Contains(userId))
          .ToListAsync());
      foreach (var group in groups)
      {
          group.MemberUserIds.Remove(userId);
          group.UpdatedAt = DateTime.UtcNow;
          integrity.Seal(group);
          session.Store(group);
      }
      return groups;
  }

  public async Task<List<Fido2AppUser>> GetMembershipsByUsernameAsync(string username)
  {
      var normalized = username.NormalizeUsername();
      return await VerifiedAsync(await session.Query<Fido2AppUser>()
          .Where(u => u.Username == normalized).ToListAsync());
  }

  public async Task<List<Tenant>> GetTenantsByIdsAsync(IEnumerable<Guid> tenantIds)
  {
      var ids = tenantIds.Distinct().ToArray();
      if (ids.Length == 0) return [];
      return await VerifiedAsync(await session.Query<Tenant>().Where(t => ids.Contains(t.Id)).ToListAsync());
  }

  public async Task<List<TenantRole>> GetRolesAsync()
  {
      var tenant = await RequireTenantAsync();
      return await VerifiedAsync(await session.Query<TenantRole>()
          .Where(r => r.TenantId == tenant.Id).ToListAsync());
  }

  public async Task<TenantRole?> GetRoleByIdAsync(Guid roleId)
  {
      var tenant = await RequireTenantAsync();
      return await VerifiedAsync(await session.Query<TenantRole>()
          .FirstOrDefaultAsync(r => r.Id == roleId && r.TenantId == tenant.Id));
  }

  public async Task<TenantRole?> GetRoleByNameAsync(string name)
  {
      var tenant = await RequireTenantAsync();
      return await VerifiedAsync(await session.Query<TenantRole>()
          .FirstOrDefaultAsync(r => r.Name == name && r.TenantId == tenant.Id));
  }

  public async Task UpsertRoleAsync(TenantRole role)
  {
      var tenant = await RequireTenantAsync();
      role.TenantId = tenant.Id;
      integrity.Seal(role);
      session.Store(role);
      await session.SaveChangesAsync();
      await anchors.RecordAsync(role);
  }

  public async Task UpsertRoleForTenantAsync(Guid tenantId, TenantRole role)
  {
      role.TenantId = tenantId;
      integrity.Seal(role);
      session.Store(role);
      await session.SaveChangesAsync();
      await anchors.RecordAsync(role);
  }

  public async Task DeleteRoleAsync(Guid roleId)
  {
      var tenant = await RequireTenantAsync();
      session.DeleteWhere<TenantRole>(r => r.Id == roleId && r.TenantId == tenant.Id);
      await session.SaveChangesAsync();
  }

  public async Task RemoveRoleFromAllUsersAsync(string roleName)
  {
      var tenant = await RequireTenantAsync();
      await RemoveRoleFromAllUsersForTenantAsync(tenant.Id, roleName);
  }

  public async Task<List<TenantGroup>> GetGroupsAsync()
  {
      var tenant = await RequireTenantAsync();
      return await GetGroupsForTenantAsync(tenant.Id);
  }

  public async Task<TenantGroup?> GetGroupByIdAsync(Guid groupId)
  {
      var tenant = await RequireTenantAsync();
      return await GetGroupByIdForTenantAsync(tenant.Id, groupId);
  }

  public async Task<TenantGroup?> GetGroupByNameAsync(string name)
  {
      var tenant = await RequireTenantAsync();
      return await GetGroupByNameForTenantAsync(tenant.Id, name);
  }

  public async Task UpsertGroupAsync(TenantGroup group)
  {
      var tenant = await RequireTenantAsync();
      await UpsertGroupForTenantAsync(tenant.Id, group);
  }

  public async Task DeleteGroupAsync(Guid groupId)
  {
      var tenant = await RequireTenantAsync();
      await DeleteGroupForTenantAsync(tenant.Id, groupId);
  }

  public async Task<List<TenantGroup>> GetGroupsForTenantAsync(Guid tenantId)
  {
      return await VerifiedAsync(await session.Query<TenantGroup>()
          .Where(g => g.TenantId == tenantId).ToListAsync());
  }

  public async Task<TenantGroup?> GetGroupByIdForTenantAsync(Guid tenantId, Guid groupId)
  {
      return await VerifiedAsync(await session.Query<TenantGroup>()
          .FirstOrDefaultAsync(g => g.Id == groupId && g.TenantId == tenantId));
  }

  public async Task<TenantGroup?> GetGroupByNameForTenantAsync(Guid tenantId, string name)
  {
      return await VerifiedAsync(await session.Query<TenantGroup>()
          .FirstOrDefaultAsync(g => g.Name == name && g.TenantId == tenantId));
  }

  public async Task UpsertGroupForTenantAsync(Guid tenantId, TenantGroup group)
  {
      group.TenantId = tenantId;
      integrity.Seal(group);
      session.Store(group);
      await session.SaveChangesAsync();
      await anchors.RecordAsync(group);
  }

  public async Task DeleteGroupForTenantAsync(Guid tenantId, Guid groupId)
  {
      // Unlink the group from every group that nests it, then delete the document.
      var parents = await VerifiedAsync(await session.Query<TenantGroup>()
          .Where(g => g.TenantId == tenantId && g.MemberGroupIds.Contains(groupId))
          .ToListAsync());
      foreach (var parent in parents)
      {
          parent.MemberGroupIds.Remove(groupId);
          parent.UpdatedAt = DateTime.UtcNow;
          integrity.Seal(parent);
          session.Store(parent);
      }
      session.DeleteWhere<TenantGroup>(g => g.Id == groupId && g.TenantId == tenantId);
      await session.SaveChangesAsync();
      foreach (var parent in parents) await anchors.RecordAsync(parent);
  }

  public async Task RemoveRoleFromAllGroupsAsync(string roleName)
  {
      var tenant = await RequireTenantAsync();
      await RemoveRoleFromAllGroupsForTenantAsync(tenant.Id, roleName);
  }

  public async Task RemoveRoleFromAllGroupsForTenantAsync(Guid tenantId, string roleName)
  {
      var groups = await VerifiedAsync(await session.Query<TenantGroup>()
          .Where(g => g.TenantId == tenantId && g.Roles.Contains(roleName))
          .ToListAsync());
      foreach (var group in groups)
      {
          group.Roles.Remove(roleName);
          group.UpdatedAt = DateTime.UtcNow;
          integrity.Seal(group);
          session.Store(group);
      }
      await session.SaveChangesAsync();
      foreach (var group in groups) await anchors.RecordAsync(group);
  }

  public async Task RevokeAllRefreshTokensAsync(Guid tenantId)
  {
      // Revoke every non-revoked refresh token belonging to the tenant. Loaded and re-sealed
      // document-by-document (not via the Patch API): IsRevoked/RevokedAt are covered by the
      // integrity seal, so a partial SQL update would invalidate it.
      var tokens = await VerifiedAsync(await session.Query<Fido2RefreshToken>()
          .Where(x => x.TenantId == tenantId && !x.IsRevoked).ToListAsync());
      await RevokeAllAsync(tokens);
  }

  public async Task<List<TenantRole>> GetRolesForTenantAsync(Guid tenantId)
  {
      return await VerifiedAsync(await session.Query<TenantRole>()
          .Where(r => r.TenantId == tenantId).ToListAsync());
  }

  public async Task<TenantRole?> GetRoleByIdForTenantAsync(Guid tenantId, Guid roleId)
  {
      return await VerifiedAsync(await session.Query<TenantRole>()
          .FirstOrDefaultAsync(r => r.Id == roleId && r.TenantId == tenantId));
  }

  public async Task<TenantRole?> GetRoleByNameForTenantAsync(Guid tenantId, string name)
  {
      return await VerifiedAsync(await session.Query<TenantRole>()
          .FirstOrDefaultAsync(r => r.Name == name && r.TenantId == tenantId));
  }

  public async Task DeleteRoleForTenantAsync(Guid tenantId, Guid roleId)
  {
      session.DeleteWhere<TenantRole>(r => r.Id == roleId && r.TenantId == tenantId);
      await session.SaveChangesAsync();
  }

  public async Task RemoveRoleFromAllUsersForTenantAsync(Guid tenantId, string roleName)
  {
      var users = await VerifiedAsync(await session.Query<Fido2AppUser>()
          .Where(u => u.TenantId == tenantId && u.Roles.Contains(roleName))
          .ToListAsync());
      foreach (var user in users)
      {
          user.Roles.Remove(roleName);
          integrity.Seal(user);
          session.Store(user);
      }
      await session.SaveChangesAsync();
      foreach (var user in users) await anchors.RecordAsync(user);
  }

  public async Task RevokeUserRefreshTokensForTenantAsync(Guid tenantId, Guid userId)
  {
      var tokens = await VerifiedAsync(await session.Query<Fido2RefreshToken>()
          .Where(x => x.UserId == userId && x.TenantId == tenantId && !x.IsRevoked).ToListAsync());
      await RevokeAllAsync(tokens);
  }

  /// <summary>Revokes already-verified refresh tokens, saves, and records their anchors.</summary>
  private async Task RevokeAllAsync(List<Fido2RefreshToken> tokens)
  {
      var now = DateTime.UtcNow;
      foreach (var token in tokens)
      {
          token.IsRevoked = true;
          token.RevokedAt = now;
          integrity.Seal(token);
          session.Store(token);
      }
      await session.SaveChangesAsync();
      foreach (var token in tokens) await anchors.RecordAsync(token);
  }
}

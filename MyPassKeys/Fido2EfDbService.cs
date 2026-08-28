using Microsoft.EntityFrameworkCore;
using StackExchange.Redis;
using Fido2NetLib;

namespace MyPassKeys;

public class Fido2EfCoreDbService(
  AppDbContext dbContext,
  IConnectionMultiplexer redis,
  ITenantService tenantService
) : IFido2DbService
{
  private async Task<Tenant> RequireTenantAsync()
  {
    var tenant = await tenantService.GetCurrentTenantAsync();
    if (tenant == null)
      throw new InvalidOperationException("The current request does not map to a known tenant.");
    return tenant;
  }

  public async Task<Fido2AppUser?> GetUserByUsernameAsync(string username)
  {
    var tenant = await RequireTenantAsync();
    return await dbContext.Users.FirstOrDefaultAsync(u => u.Username == username && u.TenantId == tenant.Id);
  }

  public async Task<Fido2AppUser?> GetUserByIdAsync(Guid userId)
  {
    var tenant = await RequireTenantAsync();
    return await dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId && u.TenantId == tenant.Id);
  }

  public async Task UpsertUserAsync(Fido2AppUser user)
  {
    var tenant = await RequireTenantAsync();
    user.TenantId = tenant.Id;
    var existingUser = await dbContext.Users.FirstOrDefaultAsync(u => u.Id == user.Id && u.TenantId == tenant.Id);
    if (existingUser == null)
    {
        dbContext.Users.Add(user);
    }
    else
    {
        dbContext.Entry(existingUser).CurrentValues.SetValues(user);
    }
    await dbContext.SaveChangesAsync();
  }

  public async Task<List<Fido2StoredCredential>> GetCredentialsByUserIdAsync(Guid userId)
  {
    var tenant = await RequireTenantAsync();
    return await dbContext.Credentials.Where(c => c.UserId == userId && c.TenantId == tenant.Id).ToListAsync();
  }

  public async Task<Fido2StoredCredential?> GetCredentialByIdAsync(byte[] credentialId)
  {
    var idString = credentialId.ToBase64Url();
    return await GetCredentialByIdAsync(idString);
  }

  public async Task<Fido2StoredCredential?> GetCredentialByIdAsync(string credentialId)
  {
    // IMPORTANT: FindAsync is not tenant-aware. We must use a query to ensure
    // we only retrieve a credential belonging to the current tenant.
    var tenant = await RequireTenantAsync();
    return await dbContext.Credentials.FirstOrDefaultAsync(c => c.Id == credentialId && c.TenantId == tenant.Id);
  }

  public async Task UpsertCredentialAsync(Fido2StoredCredential credential)
  {
    var tenant = await RequireTenantAsync();
    credential.TenantId = tenant.Id;
    var existingCredential = await dbContext.Credentials.FirstOrDefaultAsync(c => c.Id == credential.Id && c.TenantId == tenant.Id);
    if (existingCredential == null)
    {
        dbContext.Credentials.Add(credential);
    }
    else
    {
        dbContext.Entry(existingCredential).CurrentValues.SetValues(credential);
    }
    await dbContext.SaveChangesAsync();
  }

  public async Task StoreChallengeAsync(string username, string challenge)
  {
    var tenant = await RequireTenantAsync();
    var db = redis.GetDatabase();
    // Atomic Get and Delete (GETDEL) ensures the challenge is used exactly once (Replay Protection).
    // Note: Requires Redis 6.2+. If using an older version, use a Transaction.
    await db.StringSetAsync($"Challenge:{tenant.Id}:{username}", challenge, TimeSpan.FromMinutes(3));
  }

  public async Task<string?> GetChallengeAsync(string username)
  {
    var tenant = await RequireTenantAsync();
    var db = redis.GetDatabase();
    var value = await db.StringGetDeleteAsync($"Challenge:{tenant.Id}:{username}");
    return value.HasValue ? value.ToString() : null;
  }

  public async Task<Tenant?> GetTenantByHostAsync(string? host)
  {
    if (string.IsNullOrEmpty(host)) return null;
    var normalizedHost = host.ToLowerInvariant();
    return await dbContext.Set<Tenant>().FirstOrDefaultAsync(t => t.Hosts.Contains(normalizedHost));
  }

  public async Task<List<Tenant>> GetTenantsByOriginAsync(string? origin)
  {
    if (string.IsNullOrEmpty(origin)) return [];
    var normalizedOrigin = origin.TrimEnd('/');
    return await dbContext.Set<Tenant>()
      .Where(t => t.AllowedOrigins.Contains(normalizedOrigin))
      .ToListAsync();
  }

  public async Task<Tenant?> GetManagementTenantAsync()
  {
    return await dbContext.Set<Tenant>().FirstOrDefaultAsync(t => t.IsManagementTenant);
  }

  public async Task<Tenant?> GetTenantByIdAsync(Guid tenantId)
  {
    return await dbContext.Set<Tenant>().FirstOrDefaultAsync(t => t.Id == tenantId);
  }

  public async Task<Tenant?> GetTenantByIssuerAsync(string issuer)
  {
    if (string.IsNullOrEmpty(issuer)) return null;
    return await dbContext.Set<Tenant>().FirstOrDefaultAsync(t => t.JwtIssuer == issuer);
  }

  public async Task<Fido2RefreshToken?> GetRefreshTokenAsync(string token)
  {
    var tenant = await RequireTenantAsync();
    return await dbContext.Set<Fido2RefreshToken>().FirstOrDefaultAsync(t => t.Token == token && t.TenantId == tenant.Id);
  }

  public async Task UpsertRefreshTokenAsync(Fido2RefreshToken token)
  {
    var tenant = await RequireTenantAsync();
    token.TenantId = tenant.Id;
    // Filter by both Id AND TenantId to prevent cross-tenant overwrites.
    var existing = await dbContext.Set<Fido2RefreshToken>().FirstOrDefaultAsync(t => t.Id == token.Id && t.TenantId == tenant.Id);
    if (existing == null)
    {
      dbContext.Set<Fido2RefreshToken>().Add(token);
    }
    else
    {
      dbContext.Entry(existing).CurrentValues.SetValues(token);
    }
    await dbContext.SaveChangesAsync();
  }

  public async Task RevokeUserRefreshTokensAsync(Guid userId)
  {
    var tenant = await RequireTenantAsync();
    await dbContext.Set<Fido2RefreshToken>()
      .Where(t => t.UserId == userId && t.TenantId == tenant.Id && !t.IsRevoked)
      .ExecuteUpdateAsync(s => s.SetProperty(t => t.IsRevoked, true));
  }

  public async Task UpsertTenantAsync(Tenant tenant)
  {
    var existing = await dbContext.Set<Tenant>().FirstOrDefaultAsync(t => t.Id == tenant.Id);
    if (existing == null)
    {
      dbContext.Set<Tenant>().Add(tenant);
    }
    else
    {
      dbContext.Entry(existing).CurrentValues.SetValues(tenant);
    }
    await dbContext.SaveChangesAsync();
  }

  public async Task DeleteTenantAsync(Guid tenantId)
  {
    dbContext.Set<Fido2StoredCredential>().RemoveRange(
      dbContext.Set<Fido2StoredCredential>().Where(c => c.TenantId == tenantId));
    dbContext.Set<Fido2RefreshToken>().RemoveRange(
      dbContext.Set<Fido2RefreshToken>().Where(t => t.TenantId == tenantId));
    dbContext.Set<Fido2AppUser>().RemoveRange(
      dbContext.Set<Fido2AppUser>().Where(u => u.TenantId == tenantId));
    dbContext.Set<TenantRole>().RemoveRange(
      dbContext.Set<TenantRole>().Where(r => r.TenantId == tenantId));
    dbContext.Set<Tenant>().RemoveRange(
      dbContext.Set<Tenant>().Where(t => t.Id == tenantId));
    await dbContext.SaveChangesAsync();
  }

  public async Task<List<Tenant>> GetAllTenantsAsync()
  {
    return await dbContext.Set<Tenant>().ToListAsync();
  }

  public async Task<List<Fido2AppUser>> GetUsersAsync()
  {
    throw new NotImplementedException();
  }

  public async Task DeleteUserAsync(Guid userId)
  {
    throw new NotImplementedException();
  }

  // --- Portal (cross-tenant) access --- (not implemented: Marten is the active store; see CLAUDE.md)
  public Task<Fido2StoredCredential?> GetCredentialByIdForTenantsAsync(string credentialId, IReadOnlyCollection<Guid> tenantIds) => throw new NotImplementedException();
  public Task<List<Fido2StoredCredential>> GetCredentialsByUserIdForTenantAsync(Guid tenantId, Guid userId) => throw new NotImplementedException();
  public Task UpsertCredentialForTenantAsync(Guid tenantId, Fido2StoredCredential credential) => throw new NotImplementedException();
  public Task<List<Fido2AppUser>> GetUsersForTenantAsync(Guid tenantId) => throw new NotImplementedException();
  public Task<Fido2AppUser?> GetUserByIdForTenantAsync(Guid tenantId, Guid userId) => throw new NotImplementedException();
  public Task<Fido2AppUser?> GetUserByUsernameForTenantAsync(Guid tenantId, string username) => throw new NotImplementedException();
  public Task UpsertUserForTenantAsync(Guid tenantId, Fido2AppUser user) => throw new NotImplementedException();
  public Task DeleteUserForTenantAsync(Guid tenantId, Guid userId) => throw new NotImplementedException();
  public Task<List<Fido2AppUser>> GetMembershipsByUsernameAsync(string username) => throw new NotImplementedException();
  public Task<List<Tenant>> GetTenantsByIdsAsync(IEnumerable<Guid> tenantIds) => throw new NotImplementedException();

  // --- Roles --- (not implemented: Marten is the active store; see CLAUDE.md)
  public Task<List<TenantRole>> GetRolesAsync() => throw new NotImplementedException();
  public Task<TenantRole?> GetRoleByIdAsync(Guid roleId) => throw new NotImplementedException();
  public Task<TenantRole?> GetRoleByNameAsync(string name) => throw new NotImplementedException();
  public Task UpsertRoleAsync(TenantRole role) => throw new NotImplementedException();
  public Task UpsertRoleForTenantAsync(Guid tenantId, TenantRole role) => throw new NotImplementedException();
  public Task DeleteRoleAsync(Guid roleId) => throw new NotImplementedException();
  public Task RemoveRoleFromAllUsersAsync(string roleName) => throw new NotImplementedException();
  public Task<List<TenantRole>> GetRolesForTenantAsync(Guid tenantId) => throw new NotImplementedException();
  public Task<TenantRole?> GetRoleByIdForTenantAsync(Guid tenantId, Guid roleId) => throw new NotImplementedException();
  public Task<TenantRole?> GetRoleByNameForTenantAsync(Guid tenantId, string name) => throw new NotImplementedException();
  public Task DeleteRoleForTenantAsync(Guid tenantId, Guid roleId) => throw new NotImplementedException();
  public Task RemoveRoleFromAllUsersForTenantAsync(Guid tenantId, string roleName) => throw new NotImplementedException();
  public Task<List<TenantGroup>> GetGroupsAsync() => throw new NotImplementedException();
  public Task<TenantGroup?> GetGroupByIdAsync(Guid groupId) => throw new NotImplementedException();
  public Task<TenantGroup?> GetGroupByNameAsync(string name) => throw new NotImplementedException();
  public Task UpsertGroupAsync(TenantGroup group) => throw new NotImplementedException();
  public Task DeleteGroupAsync(Guid groupId) => throw new NotImplementedException();
  public Task RemoveRoleFromAllGroupsAsync(string roleName) => throw new NotImplementedException();
  public Task RemoveRoleFromAllGroupsForTenantAsync(Guid tenantId, string roleName) => throw new NotImplementedException();
  public Task<List<TenantGroup>> GetGroupsForTenantAsync(Guid tenantId) => throw new NotImplementedException();
  public Task<TenantGroup?> GetGroupByIdForTenantAsync(Guid tenantId, Guid groupId) => throw new NotImplementedException();
  public Task<TenantGroup?> GetGroupByNameForTenantAsync(Guid tenantId, string name) => throw new NotImplementedException();
  public Task UpsertGroupForTenantAsync(Guid tenantId, TenantGroup group) => throw new NotImplementedException();
  public Task DeleteGroupForTenantAsync(Guid tenantId, Guid groupId) => throw new NotImplementedException();
  public Task RevokeAllRefreshTokensAsync(Guid tenantId) => throw new NotImplementedException();
  public Task RevokeUserRefreshTokensForTenantAsync(Guid tenantId, Guid userId) => throw new NotImplementedException();
}

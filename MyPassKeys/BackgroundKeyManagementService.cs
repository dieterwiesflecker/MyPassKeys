using StackExchange.Redis;

namespace MyPassKeys;

/// <summary>
/// Runs once per hour. For each tenant:
/// 1. Auto-rotation: if KeyRotationIntervalInDays > 0 and the active key is older than that interval,
///    retire the active key and create a new one.
/// 2. Cleanup: remove retired (inactive) keys whose tokens have all expired
///    (CreatedAt + RefreshTokenLifetimeInHours has passed).
/// </summary>
public class BackgroundKeyManagementService(
    IServiceScopeFactory scopeFactory,
    ILogger<BackgroundKeyManagementService> logger
) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Key management cycle failed");
            }

            await Task.Delay(Interval, stoppingToken);
        }
    }

    private async Task RunAsync(CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        var dbService = scope.ServiceProvider.GetRequiredService<IFido2DbService>();
        var redis = scope.ServiceProvider.GetRequiredService<IConnectionMultiplexer>();
        var keyProtector = scope.ServiceProvider.GetRequiredService<IKeyProtector>();

        var tenants = await dbService.GetAllTenantsAsync();
        var now = DateTime.UtcNow;

        foreach (var tenant in tenants)
        {
            var changed = false;

            // --- Auto-rotation ---
            if (tenant.KeyRotationIntervalInDays > 0)
            {
                var activeKey = tenant.JwtKeys.FirstOrDefault(k => k.IsActive);
                if (activeKey != null)
                {
                    var age = now - activeKey.CreatedAt;
                    if (age.TotalDays >= tenant.KeyRotationIntervalInDays)
                    {
                        activeKey.IsActive = false;
                        tenant.JwtKeys.Add(TenantEndpoints.CreateKeyEntry(keyProtector));
                        changed = true;
                        logger.LogInformation(
                            "Rotated key for tenant {TenantId} (old kid: {Kid}, age: {AgeDays:F1} days)",
                            tenant.Id, activeKey.Kid, age.TotalDays);
                    }
                }
                else
                {
                    // No active key at all — create one
                    tenant.JwtKeys.Add(TenantEndpoints.CreateKeyEntry(keyProtector));
                    changed = true;
                    logger.LogWarning("Tenant {TenantId} had no active key — created one", tenant.Id);
                }
            }

            // --- Cleanup expired retired keys ---
            var cutoff = now.AddHours(-tenant.RefreshTokenLifetimeInHours);
            var expiredKeys = tenant.JwtKeys
                .Where(k => !k.IsActive && k.CreatedAt < cutoff)
                .ToList();

            if (expiredKeys.Count > 0)
            {
                foreach (var key in expiredKeys)
                    tenant.JwtKeys.Remove(key);

                changed = true;
                logger.LogInformation(
                    "Cleaned up {Count} expired key(s) for tenant {TenantId}: {Kids}",
                    expiredKeys.Count, tenant.Id, string.Join(", ", expiredKeys.Select(k => k.Kid)));
            }

            if (changed)
            {
                await dbService.UpsertTenantAsync(tenant);

                // Invalidate every Redis cache key for this tenant (host, origin, id, name,
                // management) so the rotated key set is picked up immediately. The previous
                // implementation deleted "Tenant:{host}", which never matches the actual
                // "Tenant:host:{host}" (etc.) keys, leaving a stale tenant — and thus the retired
                // signing key — cached for up to the 5-minute TTL after each rotation.
                await TenantEndpoints.InvalidateTenantCacheAsync(redis, tenant);
            }
        }
    }
}

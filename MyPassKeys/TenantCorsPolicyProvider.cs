using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.Options;

namespace MyPassKeys;

public class TenantCorsPolicyProvider(
    IOptions<CorsOptions> options,
    ILogger<TenantCorsPolicyProvider> logger) : ICorsPolicyProvider
{
    public async Task<CorsPolicy?> GetPolicyAsync(HttpContext context, string? policyName)
    {
        // Intercept the specific policy used for the frontend
        if (policyName == "AllowFrontend")
        {
            var tenantService = context.RequestServices.GetService<ITenantService>();
            if (tenantService is not null)
            {
                // Resolving the tenant touches Redis and the database. If either is
                // unavailable this must NOT crash the request — a CORS dependency
                // outage would otherwise turn every cross-origin request into a 500.
                // On failure we fall through to the static "AllowFrontend" policy.
                try
                {
                    var tenant = await tenantService.GetCurrentTenantAsync();

                    // If tenant exists and has origins, build a dynamic policy
                    if (tenant is { AllowedOrigins.Length: > 0 })
                    {
                        return new CorsPolicyBuilder()
                            .WithOrigins(tenant.AllowedOrigins)
                            .AllowAnyHeader()
                            .AllowAnyMethod()
                            .AllowCredentials()
                            .Build();
                    }
                }
                catch (AmbiguousTenantException)
                {
                    // The Origin is shared by multiple tenants (path-separated apps). The CORS
                    // preflight is an OPTIONS request that does NOT carry X-Tenant-ID, so tenant
                    // resolution is ambiguous here — but CORS is decided per-origin, not per-tenant,
                    // and an origin that multiple tenants list is by definition allowed. Reflect just
                    // that origin so the preflight succeeds; the real request carries X-Tenant-ID.
                    var origin = context.Request.Headers.Origin.FirstOrDefault();
                    if (!string.IsNullOrEmpty(origin))
                    {
                        return new CorsPolicyBuilder()
                            .WithOrigins(origin)
                            .AllowAnyHeader()
                            .AllowAnyMethod()
                            .AllowCredentials()
                            .Build();
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError(ex,
                        "Failed to resolve tenant CORS policy; falling back to the default '{PolicyName}' policy.",
                        policyName);
                }
            }
        }

        // Fallback to the default behavior (policies defined in Program.cs options)
        return options.Value.GetPolicy(policyName ?? options.Value.DefaultPolicyName);
    }
}

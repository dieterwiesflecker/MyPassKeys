using Fido2NetLib;

namespace MyPassKeys;

public class Fido2Factory(
  ITenantService tenantService,
  IConfiguration configuration,
  IHttpContextAccessor httpContextAccessor)
  : IFido2Factory
{
  public async Task<IFido2> CreateAsync()
  {
    var tenant = await tenantService.GetCurrentTenantAsync();
    if (tenant == null)
    {
      throw new InvalidOperationException("Could not determine the current tenant from the request hostname.");
    }

    // Derive rpId from the Origin header (the client's domain), falling back to the Host header.
    // This allows cross-origin clients to use their own domain as the relying party ID,
    // which is required for WebAuthn since the browser enforces rpId matches the page origin.
    var originHeader = httpContextAccessor.HttpContext?.Request.Headers.Origin.FirstOrDefault();
    string serverDomain;

    if (!string.IsNullOrEmpty(originHeader) && Uri.TryCreate(originHeader, UriKind.Absolute, out var originUri))
    {
      var originHost = originUri.Host;
      // Check ServerDomains for an explicit mapping (e.g., "app.example.com" → "example.com")
      if (!tenant.ServerDomains.TryGetValue(originHost, out serverDomain!))
      {
        serverDomain = originHost;
      }
    }
    else
    {
      var hostString = httpContextAccessor.HttpContext?.Request.Host ?? new HostString("");
      var hostKey = hostString.Value ?? "";
      if (!tenant.ServerDomains.TryGetValue(hostKey, out serverDomain!))
      {
        serverDomain = hostString.Host;
      }
    }

    var config = new Fido2Configuration
    {
      ServerDomain = serverDomain,
      ServerName = tenant.ServerName,
      Origins = new HashSet<string>(tenant.AllowedOrigins),
      TimestampDriftTolerance = configuration.GetValue("Fido2:TimestampDriftTolerance", 300000),
      ServerIcon = tenant.ServerIcon,
    };

    return new Fido2(config);
  }
}

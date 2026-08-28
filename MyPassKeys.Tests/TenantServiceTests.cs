using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using StackExchange.Redis;
using Xunit;

namespace MyPassKeys.Tests;

// ---------------------------------------------------------------------------
// TenantService resolution tests
//
// Covers the two-step resolver in TenantService.GetCurrentTenantAsync:
//   1. Host NOT in MyPassKeys:DeploymentHosts → look up Tenant.Hosts (custom subdomain).
//   2. Host IS a deployment host → match Origin against Tenant.AllowedOrigins.
// Plus the Redis cache layer that fronts both lookups.
// ---------------------------------------------------------------------------

public class TenantServiceTests
{
    private static readonly string[] DeploymentHosts = ["auth.example.com", "localhost:5205"];

    /// <summary>
    /// Real integrity service with a fixed test key. TenantService verifies every resolved
    /// tenant's seal (both the DB and the Redis cache-hit path), so test tenants must be sealed.
    /// </summary>
    private static readonly IDocumentIntegrity TestIntegrity =
        new HmacDocumentIntegrity(Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="));

    private static Tenant Sealed(Tenant tenant)
    {
        TestIntegrity.Seal(tenant);
        return tenant;
    }

    // -----------------------------------------------------------------------
    // Host-based resolution (custom subdomain mode)
    // -----------------------------------------------------------------------

    [Fact]
    public async Task CustomSubdomainHost_ResolvesViaTenantHosts()
    {
        var tenant = Sealed(new Tenant { Id = Guid.NewGuid(), Hosts = ["auth.acme.com"] });

        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantByHostAsync("auth.acme.com")).ReturnsAsync(tenant);

        var service = BuildService(dbService.Object, host: "auth.acme.com");

        var resolved = await service.GetCurrentTenantAsync();

        resolved.Should().NotBeNull();
        resolved!.Id.Should().Be(tenant.Id);
        dbService.Verify(s => s.GetTenantsByOriginAsync(It.IsAny<string>()), Times.Never,
            "Origin lookup should be skipped when Host already identifies the tenant");
    }

    [Fact]
    public async Task CustomSubdomainHost_NormalizesToLowerCase()
    {
        var tenant = Sealed(new Tenant { Id = Guid.NewGuid(), Hosts = ["auth.acme.com"] });

        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantByHostAsync("auth.acme.com")).ReturnsAsync(tenant);

        var service = BuildService(dbService.Object, host: "AUTH.ACME.com");

        var resolved = await service.GetCurrentTenantAsync();

        resolved.Should().NotBeNull();
        resolved!.Id.Should().Be(tenant.Id);
    }

    [Fact]
    public async Task UnknownHost_NotDeployment_NotAnyTenantHost_ReturnsNull()
    {
        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantByHostAsync(It.IsAny<string>())).ReturnsAsync((Tenant?)null);

        var service = BuildService(dbService.Object, host: "evil.example.com");

        var resolved = await service.GetCurrentTenantAsync();

        resolved.Should().BeNull();
        dbService.Verify(s => s.GetTenantsByOriginAsync(It.IsAny<string>()), Times.Never,
            "Non-deployment unknown hosts must not fall back to origin lookup — that would let any unknown host enumerate tenants by origin");
    }

    [Fact]
    public async Task TamperedTenant_FailsResolution()
    {
        // Models a direct DB (or Redis cache) write flipping a sealed security field: the
        // resolver must throw rather than serve the tampered tenant.
        var tenant = Sealed(new Tenant { Id = Guid.NewGuid(), Hosts = ["auth.acme.com"] });
        tenant.IsManagementTenant = true;

        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantByHostAsync("auth.acme.com")).ReturnsAsync(tenant);

        var service = BuildService(dbService.Object, host: "auth.acme.com");

        await Assert.ThrowsAsync<DocumentTamperedException>(() => service.GetCurrentTenantAsync());
    }

    // -----------------------------------------------------------------------
    // Origin-based resolution (default mode, on a deployment host)
    // -----------------------------------------------------------------------

    [Fact]
    public async Task DeploymentHost_WithMatchingOrigin_ResolvesViaAllowedOrigins()
    {
        var tenant = Sealed(new Tenant
        {
            Id = Guid.NewGuid(),
            AllowedOrigins = ["https://evento.example.org"]
        });

        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantsByOriginAsync("https://evento.example.org")).ReturnsAsync([tenant]);

        var service = BuildService(dbService.Object,
            host: "auth.example.com",
            origin: "https://evento.example.org");

        var resolved = await service.GetCurrentTenantAsync();

        resolved.Should().NotBeNull();
        resolved!.Id.Should().Be(tenant.Id);
        dbService.Verify(s => s.GetTenantByHostAsync(It.IsAny<string>()), Times.Never,
            "Host-based lookup should be skipped when the Host is a deployment host");
    }

    [Fact]
    public async Task DeploymentHost_WithTrailingSlashOrigin_TrimsBeforeLookup()
    {
        var tenant = Sealed(new Tenant
        {
            Id = Guid.NewGuid(),
            AllowedOrigins = ["https://evento.example.org"]
        });

        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantsByOriginAsync("https://evento.example.org")).ReturnsAsync([tenant]);

        var service = BuildService(dbService.Object,
            host: "auth.example.com",
            origin: "https://evento.example.org/");

        var resolved = await service.GetCurrentTenantAsync();

        resolved.Should().NotBeNull();
        resolved!.Id.Should().Be(tenant.Id);
    }

    [Fact]
    public async Task DeploymentHost_WithoutOrigin_ReturnsNull()
    {
        var dbService = new Mock<IFido2DbService>();

        var service = BuildService(dbService.Object, host: "auth.example.com", origin: null);

        var resolved = await service.GetCurrentTenantAsync();

        resolved.Should().BeNull("origin is required to pick a tenant on a shared deployment host");
        dbService.Verify(s => s.GetTenantByHostAsync(It.IsAny<string>()), Times.Never);
        dbService.Verify(s => s.GetTenantsByOriginAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task DeploymentHost_WithUnknownOrigin_ReturnsNull()
    {
        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantsByOriginAsync(It.IsAny<string>())).ReturnsAsync([]);

        var service = BuildService(dbService.Object,
            host: "auth.example.com",
            origin: "https://attacker.example.com");

        var resolved = await service.GetCurrentTenantAsync();

        resolved.Should().BeNull();
    }

    [Fact]
    public async Task DeploymentHost_IsCaseInsensitive()
    {
        var tenant = Sealed(new Tenant
        {
            Id = Guid.NewGuid(),
            AllowedOrigins = ["https://evento.example.org"]
        });

        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantsByOriginAsync("https://evento.example.org")).ReturnsAsync([tenant]);

        var service = BuildService(dbService.Object,
            host: "Auth.Example.Com",
            origin: "https://evento.example.org");

        var resolved = await service.GetCurrentTenantAsync();

        resolved.Should().NotBeNull("deployment-host comparison must be case-insensitive — DNS is");
    }

    // -----------------------------------------------------------------------
    // X-Tenant-ID is authoritative (strict — no fallback on miss)
    // -----------------------------------------------------------------------

    [Fact]
    public async Task XTenantId_ByServerName_NotFound_ReturnsNull_DoesNotFallBackToOrigin()
    {
        // Header present but its ServerName matches nothing. Even though the Origin WOULD resolve
        // a tenant, the resolver must NOT fall back — a present-but-unresolved X-Tenant-ID is a
        // client error, and silent fallback could mis-route to a different tenant.
        var originTenant = Sealed(new Tenant { Id = Guid.NewGuid(), AllowedOrigins = ["https://abc.com"] });

        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantByServerNameAsync("passkeysApp")).ReturnsAsync((Tenant?)null);
        dbService.Setup(s => s.GetTenantsByOriginAsync("https://abc.com")).ReturnsAsync([originTenant]);

        var service = BuildService(dbService.Object, host: "auth.example.com",
            origin: "https://abc.com", xTenantId: "passkeysApp");

        var resolved = await service.GetCurrentTenantAsync();

        resolved.Should().BeNull();
        dbService.Verify(s => s.GetTenantsByOriginAsync(It.IsAny<string>()), Times.Never,
            "a present X-Tenant-ID is authoritative — it must not fall through to Origin resolution");
        dbService.Verify(s => s.GetTenantByHostAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task XTenantId_ByUuid_NotFound_ReturnsNull()
    {
        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantByIdAsync(It.IsAny<Guid>())).ReturnsAsync((Tenant?)null);

        var service = BuildService(dbService.Object, host: "auth.example.com",
            origin: "https://abc.com", xTenantId: Guid.NewGuid().ToString());

        var resolved = await service.GetCurrentTenantAsync();

        resolved.Should().BeNull();
        dbService.Verify(s => s.GetTenantsByOriginAsync(It.IsAny<string>()), Times.Never);
    }

    // -----------------------------------------------------------------------
    // Shared-origin disambiguation (path-separated tenants)
    // -----------------------------------------------------------------------

    [Fact]
    public async Task DeploymentHost_SharedOrigin_NoXTenantId_Throws()
    {
        // Two non-management tenants list the same origin (abc.com/a-app and abc.com/b-app).
        // Without X-Tenant-ID the resolver cannot pick one safely — it must surface the ambiguity
        // rather than guess, otherwise a tenant could claim another's origin and win resolution.
        var a = Sealed(new Tenant { Id = Guid.NewGuid(), AllowedOrigins = ["https://abc.com"] });
        var b = Sealed(new Tenant { Id = Guid.NewGuid(), AllowedOrigins = ["https://abc.com"] });

        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantsByOriginAsync("https://abc.com")).ReturnsAsync([a, b]);

        var service = BuildService(dbService.Object, host: "auth.example.com", origin: "https://abc.com");

        await Assert.ThrowsAsync<AmbiguousTenantException>(() => service.GetCurrentTenantAsync());
    }

    [Fact]
    public async Task DeploymentHost_SharedOrigin_WithXTenantId_ResolvesExplicitTenant()
    {
        var a = Sealed(new Tenant { Id = Guid.NewGuid(), AllowedOrigins = ["https://abc.com"] });
        var b = Sealed(new Tenant { Id = Guid.NewGuid(), AllowedOrigins = ["https://abc.com"] });

        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantByIdAsync(b.Id)).ReturnsAsync(b);

        var service = BuildService(dbService.Object, host: "auth.example.com",
            origin: "https://abc.com", xTenantId: b.Id.ToString());

        var resolved = await service.GetCurrentTenantAsync();

        resolved!.Id.Should().Be(b.Id);
        dbService.Verify(s => s.GetTenantsByOriginAsync(It.IsAny<string>()), Times.Never,
            "X-Tenant-ID short-circuits origin resolution, so the ambiguity never arises");
    }

    [Fact]
    public async Task DeploymentHost_SharedOrigin_ManagementTenantWins()
    {
        // The management tenant cannot be impersonated (the flag is never settable via the API),
        // so it deterministically wins a shared origin instead of throwing.
        var management = Sealed(new Tenant { Id = Guid.NewGuid(), IsManagementTenant = true, AllowedOrigins = ["https://abc.com"] });
        var customer = Sealed(new Tenant { Id = Guid.NewGuid(), AllowedOrigins = ["https://abc.com"] });

        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantsByOriginAsync("https://abc.com")).ReturnsAsync([customer, management]);

        var service = BuildService(dbService.Object, host: "auth.example.com", origin: "https://abc.com");

        var resolved = await service.GetCurrentTenantAsync();

        resolved!.Id.Should().Be(management.Id);
    }

    // -----------------------------------------------------------------------
    // Cache key isolation
    //
    // The resolver caches host and origin lookups under distinct Redis keys
    // (Tenant:host:{host} vs Tenant:origin:{origin}). A host-cached entry must
    // not leak into an origin-cached resolution and vice versa.
    // -----------------------------------------------------------------------

    [Fact]
    public async Task HostAndOriginUseDistinctCacheKeys()
    {
        var hostTenant = Sealed(new Tenant { Id = Guid.NewGuid(), Hosts = ["auth.acme.com"] });
        var originTenant = Sealed(new Tenant
        {
            Id = Guid.NewGuid(),
            AllowedOrigins = ["https://evento.example.org"]
        });

        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(s => s.GetTenantByHostAsync("auth.acme.com")).ReturnsAsync(hostTenant);
        dbService.Setup(s => s.GetTenantsByOriginAsync("https://evento.example.org")).ReturnsAsync([originTenant]);

        var redis = BuildInMemoryRedis();

        // First request: custom subdomain, no Origin header.
        var resolvedByHost = await BuildService(dbService.Object, redis,
            host: "auth.acme.com").GetCurrentTenantAsync();

        // Second request: deployment host + Origin — must NOT see the previous host cache entry.
        var resolvedByOrigin = await BuildService(dbService.Object, redis,
            host: "auth.example.com", origin: "https://evento.example.org").GetCurrentTenantAsync();

        resolvedByHost!.Id.Should().Be(hostTenant.Id);
        resolvedByOrigin!.Id.Should().Be(originTenant.Id);
    }

    // -----------------------------------------------------------------------
    // Test infrastructure
    // -----------------------------------------------------------------------

    private static TenantService BuildService(
        IFido2DbService dbService,
        string host,
        string? origin = null,
        string? xTenantId = null)
        => BuildService(dbService, BuildInMemoryRedis(), host, origin, xTenantId);

    private static TenantService BuildService(
        IFido2DbService dbService,
        IConnectionMultiplexer redis,
        string host,
        string? origin = null,
        string? xTenantId = null)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Host = new HostString(host);
        if (origin is not null)
            httpContext.Request.Headers["Origin"] = origin;
        if (xTenantId is not null)
            httpContext.Request.Headers["X-Tenant-ID"] = xTenantId;

        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        httpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var services = new ServiceCollection();
        services.AddSingleton(dbService);
        var serviceProvider = services.BuildServiceProvider();

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["MyPassKeys:DeploymentHosts:0"] = DeploymentHosts[0],
                ["MyPassKeys:DeploymentHosts:1"] = DeploymentHosts[1]
            })
            .Build();

        return new TenantService(
            httpContextAccessor.Object,
            serviceProvider,
            redis,
            configuration,
            NullLogger<TenantService>.Instance,
            TestIntegrity,
            new RedisVersionAnchor(redis, NullLogger<RedisVersionAnchor>.Instance));
    }

    /// <summary>
    /// Builds an IConnectionMultiplexer whose IDatabase is backed by an in-memory dictionary.
    /// Only the StringGetAsync / StringSetAsync overloads used by RedisExtensions.GetOrCreateAsync
    /// are wired — anything else throws, which surfaces unexpected Redis usage in tests.
    /// </summary>
    private static IConnectionMultiplexer BuildInMemoryRedis()
    {
        var store = new Dictionary<string, string>();

        var db = new Mock<IDatabase>();

        db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .Returns<RedisKey, CommandFlags>((key, _) =>
                Task.FromResult(store.TryGetValue(key.ToString(), out var value)
                    ? (RedisValue)value
                    : RedisValue.Null));

        // The 4-arg overload is what RedisVersionAnchor.RecordAsync binds to.
        db.Setup(d => d.StringSetAsync(
                It.IsAny<RedisKey>(),
                It.IsAny<RedisValue>(),
                It.IsAny<TimeSpan?>(),
                It.IsAny<When>()))
            .Returns<RedisKey, RedisValue, TimeSpan?, When>(
                (key, value, _, _) =>
                {
                    store[key.ToString()] = value.ToString();
                    return Task.FromResult(true);
                });

        // Two overloads: 5-arg (legacy) and 6-arg (with keepTtl). Without knowing which the
        // C# compiler binds RedisExtensions.GetOrCreateAsync to, set up both — same backing store.
        db.Setup(d => d.StringSetAsync(
                It.IsAny<RedisKey>(),
                It.IsAny<RedisValue>(),
                It.IsAny<TimeSpan?>(),
                It.IsAny<When>(),
                It.IsAny<CommandFlags>()))
            .Returns<RedisKey, RedisValue, TimeSpan?, When, CommandFlags>(
                (key, value, _, _, _) =>
                {
                    store[key.ToString()] = value.ToString();
                    return Task.FromResult(true);
                });

        db.Setup(d => d.StringSetAsync(
                It.IsAny<RedisKey>(),
                It.IsAny<RedisValue>(),
                It.IsAny<TimeSpan?>(),
                It.IsAny<bool>(),
                It.IsAny<When>(),
                It.IsAny<CommandFlags>()))
            .Returns<RedisKey, RedisValue, TimeSpan?, bool, When, CommandFlags>(
                (key, value, _, _, _, _) =>
                {
                    store[key.ToString()] = value.ToString();
                    return Task.FromResult(true);
                });

        var multiplexer = new Mock<IConnectionMultiplexer>();
        multiplexer.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object?>()))
                   .Returns(db.Object);

        return multiplexer.Object;
    }
}

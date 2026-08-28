using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IdentityModel.Tokens.Jwt;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using StackExchange.Redis;
using Xunit;
using MyPassKeys.Tests.Helpers;

namespace MyPassKeys.Tests;

// ---------------------------------------------------------------------------
// Shared base class
// ---------------------------------------------------------------------------

public abstract class TokenServiceTestBase
{
    private static IConfiguration BuildConfig()
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"]    = "https://fallback.localhost",
                ["Jwt:Audience"]  = "api://fallback.localhost"
            })
            .Build();
    }

    /// <summary>
    /// Fixed-key protector shared by all tests — key entries created via MakeKeyEntry are
    /// encrypted at rest exactly like production, so GenerateTokenAsync exercises the
    /// decrypt-before-sign path.
    /// </summary>
    protected static readonly IKeyProtector TestKeyProtector =
        new AesGcmKeyProtector(Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="));

    protected static JwtKeyEntry MakeKeyEntry()
    {
        return TenantEndpoints.CreateKeyEntry(TestKeyProtector);
    }

    protected static Tenant MakeTenant(
        JwtKeyEntry? keyEntry = null,
        string issuer      = "https://test.localhost",
        string audience    = "api://test.localhost")
    {
        var key = keyEntry ?? MakeKeyEntry();

        return new Tenant
        {
            Id                        = Guid.CreateVersion7(),
            Hosts                     = ["test.localhost"],
            ServerDomains             = new Dictionary<string, string> { ["test.localhost"] = "test.localhost" },
            JwtIssuer                 = issuer,
            JwtAudience               = audience,
            JwtKeys                   = [key],
            AccessTokenLifetimeInMinutes  = 60,
            RefreshTokenLifetimeInHours   = 720
        };
    }

    protected static Fido2AppUser MakeUser() =>
        new()
        {
            Id          = Guid.CreateVersion7(),
            TenantId    = Guid.CreateVersion7(),
            Username    = "testuser@example.com",
            DisplayName = "Test User",
            Roles       = ["user"]
        };

    /// <summary>
    /// Creates a TokenService wired to a mock Redis whose JTI store is shared between
    /// the synchronous StringSet (used by ValidateTokenAsync) and the asynchronous
    /// StringSetAsync (used by GetDpopKeyFromProof).
    /// </summary>
    protected static TokenService MakeService(Tenant? tenant = null, List<TenantRole>? roleCatalog = null, List<TenantGroup>? groups = null)
    {
        var resolvedTenant = tenant ?? MakeTenant();

        var tenantService = new Mock<ITenantService>();
        tenantService
            .Setup(s => s.GetCurrentTenantAsync())
            .ReturnsAsync(resolvedTenant);

        return BuildTokenService(tenantService.Object, roleCatalog, groups);
    }

    protected static TokenService MakeServiceWithNullTenant()
    {
        var tenantService = new Mock<ITenantService>();
        tenantService
            .Setup(s => s.GetCurrentTenantAsync())
            .ReturnsAsync((Tenant?)null);

        return BuildTokenService(tenantService.Object);
    }

    private static TokenService BuildTokenService(ITenantService tenantService, List<TenantRole>? roleCatalog = null, List<TenantGroup>? groups = null)
    {
        // Shared JTI store — models Redis SET NX behaviour.
        var jtiStore = new HashSet<string>();

        var db = new Mock<IDatabase>();

        // Synchronous StringSet — matches the 4-param overload (RedisKey, RedisValue, TimeSpan?, When)
        // that ValidateTokenAsync calls. The 5-param overload (with CommandFlags) is a separate method;
        // mocking the wrong overload causes Moq to return the default (false) for every call.
        db.Setup(d => d.StringSet(
                It.IsAny<RedisKey>(),
                It.IsAny<RedisValue>(),
                It.IsAny<TimeSpan?>(),
                It.IsAny<When>()))
            .Returns<RedisKey, RedisValue, TimeSpan?, When>(
                (key, _, _, when) => when != When.NotExists || jtiStore.Add(key.ToString()));

        // Asynchronous StringSetAsync — matches the 4-param overload (RedisKey, RedisValue, TimeSpan?, When)
        // that GetDpopKeyFromProof calls. Use .Returns<T1..T4> so the lambda runs per-invocation.
        db.Setup(d => d.StringSetAsync(
                It.IsAny<RedisKey>(),
                It.IsAny<RedisValue>(),
                It.IsAny<TimeSpan?>(),
                It.IsAny<When>()))
            .Returns<RedisKey, RedisValue, TimeSpan?, When>(
                (key, _, _, when) => Task.FromResult(
                    when != When.NotExists || jtiStore.Add(key.ToString())));

        var multiplexer = new Mock<IConnectionMultiplexer>();
        multiplexer.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object?>()))
                   .Returns(db.Object);

        // Role catalog is empty by default — token generation then emits no 'scp' claim.
        var dbService = new Mock<IFido2DbService>();
        dbService.Setup(d => d.GetRolesAsync())
                 .ReturnsAsync(roleCatalog ?? new List<TenantRole>());
        // Group list is empty by default — no group-derived roles and no 'groups' claims.
        dbService.Setup(d => d.GetGroupsAsync())
                 .ReturnsAsync(groups ?? new List<TenantGroup>());

        return new TokenService(
            BuildConfig(),
            multiplexer.Object,
            NullLogger<TokenService>.Instance,
            tenantService,
            dbService.Object,
            TestKeyProtector);
    }

    protected static string ComputeAth(string accessToken)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(accessToken));
        return Base64UrlEncoder.Encode(hash);
    }
}

// ---------------------------------------------------------------------------
// GenerateToken tests
// ---------------------------------------------------------------------------

public class TokenService_GenerateToken : TokenServiceTestBase
{
    [Fact]
    public async Task GenerateToken_NullTenant_Throws()
    {
        var service = MakeServiceWithNullTenant();
        var user    = MakeUser();

        var act = async () => await service.GenerateTokenAsync(user);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task GenerateToken_UsesTenantSigningKey()
    {
        var keyA    = MakeKeyEntry();
        var keyB    = MakeKeyEntry();
        var tenant  = MakeTenant(keyEntry: keyA);
        var service = MakeService(tenant);
        var user    = MakeUser();

        var token = await service.GenerateTokenAsync(user);

        // Validate with the correct tenant public key — should succeed.
        var handler          = new JwtSecurityTokenHandler();
        var validationParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey         = new JsonWebKey(keyA.PublicKey.GetRawText()),
            ValidateIssuer           = false,
            ValidateAudience         = false,
            ClockSkew                = TimeSpan.Zero
        };
        var principal = handler.ValidateToken(token, validationParams, out _);
        principal.Should().NotBeNull();

        // Validate with a different key — should throw (i.e. token is bound to the tenant key).
        var wrongValidationParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey         = new JsonWebKey(keyB.PublicKey.GetRawText()),
            ValidateIssuer           = false,
            ValidateAudience         = false,
            ClockSkew                = TimeSpan.Zero
        };
        var act = () => handler.ValidateToken(token, wrongValidationParams, out _);
        act.Should().Throw<SecurityTokenSignatureKeyNotFoundException>();
    }

    [Fact]
    public async Task GenerateToken_UsesTenantIssuerAndAudience()
    {
        var tenant  = MakeTenant(issuer: "https://my-tenant.example.com", audience: "api://my-tenant");
        var service = MakeService(tenant);
        var user    = MakeUser();

        var token   = await service.GenerateTokenAsync(user);
        var handler = new JwtSecurityTokenHandler();
        var jwt     = handler.ReadJwtToken(token);

        jwt.Issuer.Should().Be("https://my-tenant.example.com");
        jwt.Audiences.Should().Contain("api://my-tenant");
    }

    [Fact]
    public async Task GenerateToken_WithDpopKey_HasCnfClaim()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var user          = MakeUser();

        var token   = await service.GenerateTokenAsync(user, builder.PublicJwkJson);
        var handler = new JwtSecurityTokenHandler();
        var jwt     = handler.ReadJwtToken(token);

        var cnf = jwt.Payload["cnf"];
        cnf.Should().NotBeNull();
        cnf!.ToString().Should().Contain("jkt");
    }

    [Fact]
    public async Task GenerateToken_WithoutDpopKey_NoCnfClaim()
    {
        var service = MakeService();
        var user    = MakeUser();

        var token   = await service.GenerateTokenAsync(user);
        var handler = new JwtSecurityTokenHandler();
        var jwt     = handler.ReadJwtToken(token);

        jwt.Payload.ContainsKey("cnf").Should().BeFalse();
    }
}

// ---------------------------------------------------------------------------
// ValidateToken tests
// ---------------------------------------------------------------------------

public class TokenService_ValidateToken : TokenServiceTestBase
{
    private const string DefaultHtm = "POST";
    private const string DefaultHtu = "https://localhost/auth/make-assertion";

    [Fact]
    public async Task ValidateToken_ValidToken_NoSpoofing_ReturnsPrincipal()
    {
        var service = MakeService();
        var user    = MakeUser();

        var token     = await service.GenerateTokenAsync(user);
        var principal = await service.ValidateTokenAsync(token);

        principal.Should().NotBeNull();
        principal!.FindFirstValue(ClaimTypes.NameIdentifier).Should().Be(user.Id.ToString());
    }

    // Regression: JwtSecurityTokenHandler's DefaultInboundClaimTypeMap renames "scp" to the
    // long-form Microsoft URI on validation, which made FindFirst("scp") return null and every
    // permission gate (AuthorizePermissionAsync et al.) 403 despite a valid scope. ValidateTokenAsync
    // must remove that mapping so the "scp" claim survives with its original name and value.
    [Fact]
    public async Task ValidateToken_PreservesScpClaim_NotRemappedByInboundMap()
    {
        var catalog = new List<TenantRole>
        {
            new()
            {
                Name = "tenantadmin",
                Permissions = ["users:read", "users:write", "roles:read", "roles:manage"]
            }
        };
        var tenant  = MakeTenant();
        var service = MakeService(tenant, catalog);
        var user    = new Fido2AppUser
        {
            Id          = Guid.CreateVersion7(),
            TenantId    = Guid.CreateVersion7(),
            Username    = "admin@example.com",
            DisplayName = "Admin User",
            Roles       = ["tenantadmin"]
        };

        var token     = await service.GenerateTokenAsync(user);
        var principal = await service.ValidateTokenAsync(token);

        principal.Should().NotBeNull();

        // The claim must be findable under its original short name — not the remapped URI.
        var scp = principal!.FindFirst("scp")?.Value;
        scp.Should().NotBeNull("the 'scp' claim must not be renamed by the inbound claim-type map");
        scp!.Split(' ').Should().Contain("users:read")
            .And.Contain("roles:manage");
    }

    // A user with no direct roles who sits in a group nested inside another group must receive
    // the roles attached to BOTH groups (AD-style inheritance), the corresponding permissions in
    // 'scp', and one 'groups' claim per effective group.
    [Fact]
    public async Task GenerateToken_GroupMembership_EmitsInheritedRolesAndGroupsClaims()
    {
        var catalog = new List<TenantRole>
        {
            new() { Name = "developer", Permissions = ["repos:write"] },
            new() { Name = "employee",  Permissions = ["users:read"] }
        };
        var user = new Fido2AppUser
        {
            Id          = Guid.CreateVersion7(),
            Username    = "dev@example.com",
            DisplayName = "Dev",
            Roles       = []
        };
        var team    = new TenantGroup { Name = "team",    Roles = ["developer"], MemberUserIds = [user.Id] };
        var company = new TenantGroup { Name = "company", Roles = ["employee"],  MemberGroupIds = [team.Id] };
        var service = MakeService(MakeTenant(), catalog, groups: [team, company]);

        var token = await service.GenerateTokenAsync(user);
        var jwt   = new JwtSecurityTokenHandler().ReadJwtToken(token);

        jwt.Claims.Where(c => c.Type == "roles").Select(c => c.Value)
            .Should().BeEquivalentTo("developer", "employee");
        jwt.Claims.Where(c => c.Type == "groups").Select(c => c.Value)
            .Should().BeEquivalentTo("team", "company");
        jwt.Claims.Single(c => c.Type == "scp").Value.Split(' ')
            .Should().BeEquivalentTo("repos:write", "users:read");
    }

    [Fact]
    public async Task ValidateToken_ExpiredToken_ReturnsNull()
    {
        var tenant  = MakeTenant();
        var service = MakeService(tenant);
        var user    = MakeUser();

        // Build an already-expired token manually using the tenant's private key
        // (stored encrypted at rest — decrypt it first, as TokenService does).
        var privateJwk = TestKeyProtector.Unprotect(tenant.JwtKeys[0].PrivateKey, tenant.JwtKeys[0].Kid);
        var jwk = new JsonWebKey(privateJwk.GetRawText());
        var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = Base64UrlEncoder.DecodeBytes(jwk.D),
            Q = new ECPoint
            {
                X = Base64UrlEncoder.DecodeBytes(jwk.X),
                Y = Base64UrlEncoder.DecodeBytes(jwk.Y)
            }
        });
        var signingKey = new ECDsaSecurityKey(ecdsa) { KeyId = jwk.KeyId };
        var handler    = new JwtSecurityTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Subject            = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())]),
            NotBefore          = DateTime.UtcNow.AddMinutes(-20),
            Expires            = DateTime.UtcNow.AddMinutes(-10),
            Issuer             = tenant.JwtIssuer,
            Audience           = tenant.JwtAudience,
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.EcdsaSha256)
        };
        var expiredToken = handler.WriteToken(handler.CreateToken(descriptor));

        var principal = await service.ValidateTokenAsync(expiredToken);

        principal.Should().BeNull();
    }

    [Fact]
    public async Task ValidateToken_WrongSigningKey_CrossTenantIsolation_ReturnsNull()
    {
        // Tenant A and tenant B share the same issuer/audience but have different signing keys.
        var tenantA    = MakeTenant(issuer: "https://shared.example.com", audience: "api://shared");
        var tenantB    = MakeTenant(issuer: "https://shared.example.com", audience: "api://shared");
        var serviceA   = MakeService(tenantA);
        var serviceB   = MakeService(tenantB);
        var user       = MakeUser();

        // Token signed with tenant A's key.
        var token = await serviceA.GenerateTokenAsync(user);

        // Validate with service configured for tenant B (different key) — must fail.
        var principal = await serviceB.ValidateTokenAsync(token);

        principal.Should().BeNull();
    }

    [Fact]
    public async Task ValidateToken_DpopBound_MissingProof_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var user          = MakeUser();

        var token     = await service.GenerateTokenAsync(user, builder.PublicJwkJson);
        var principal = await service.ValidateTokenAsync(token); // No DPoP proof supplied

        principal.Should().BeNull();
    }

    [Fact]
    public async Task ValidateToken_DpopBound_ValidProof_ReturnsPrincipal()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var user          = MakeUser();

        var accessToken = await service.GenerateTokenAsync(user, builder.PublicJwkJson);
        var ath         = ComputeAth(accessToken);
        var proof       = builder.Build(htm: DefaultHtm, htu: DefaultHtu, ath: ath);

        var principal = await service.ValidateTokenAsync(accessToken, proof, DefaultHtm, DefaultHtu);

        principal.Should().NotBeNull();
        principal!.FindFirstValue(ClaimTypes.NameIdentifier).Should().Be(user.Id.ToString());
    }

    [Fact]
    public async Task ValidateToken_DpopBound_WrongTyp_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var user          = MakeUser();

        var accessToken = await service.GenerateTokenAsync(user, builder.PublicJwkJson);
        var ath         = ComputeAth(accessToken);
        var proof       = builder.Build(htm: DefaultHtm, htu: DefaultHtu, ath: ath, typ: "JWT");

        var principal = await service.ValidateTokenAsync(accessToken, proof, DefaultHtm, DefaultHtu);

        principal.Should().BeNull();
    }

    [Fact]
    public async Task ValidateToken_DpopBound_WrongAth_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var user          = MakeUser();

        var accessToken = await service.GenerateTokenAsync(user, builder.PublicJwkJson);
        var wrongAth    = ComputeAth("this-is-not-the-access-token");
        var proof       = builder.Build(htm: DefaultHtm, htu: DefaultHtu, ath: wrongAth);

        var principal = await service.ValidateTokenAsync(accessToken, proof, DefaultHtm, DefaultHtu);

        principal.Should().BeNull();
    }

    [Fact]
    public async Task ValidateToken_DpopBound_MissingAth_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var user          = MakeUser();

        var accessToken = await service.GenerateTokenAsync(user, builder.PublicJwkJson);
        // Build proof without ath — omit by not passing it (ath defaults to null in Build)
        var proof = builder.Build(htm: DefaultHtm, htu: DefaultHtu);

        var principal = await service.ValidateTokenAsync(accessToken, proof, DefaultHtm, DefaultHtu);

        principal.Should().BeNull();
    }

    [Fact]
    public async Task ValidateToken_DpopBound_StaleIat_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var user          = MakeUser();

        var accessToken = await service.GenerateTokenAsync(user, builder.PublicJwkJson);
        var ath         = ComputeAth(accessToken);
        // iat is 10 minutes ago — outside the 5-minute window
        var staleIat = DateTimeOffset.UtcNow.AddMinutes(-10);
        var proof    = builder.Build(htm: DefaultHtm, htu: DefaultHtu, ath: ath, iat: staleIat);

        var principal = await service.ValidateTokenAsync(accessToken, proof, DefaultHtm, DefaultHtu);

        principal.Should().BeNull();
    }

    [Fact]
    public async Task ValidateToken_DpopBound_ReplayedJti_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var user          = MakeUser();

        var accessToken = await service.GenerateTokenAsync(user, builder.PublicJwkJson);
        var ath         = ComputeAth(accessToken);
        var fixedJti    = Guid.NewGuid().ToString();
        var proof       = builder.Build(htm: DefaultHtm, htu: DefaultHtu, ath: ath, jti: fixedJti);

        // First use — should succeed.
        var first = await service.ValidateTokenAsync(accessToken, proof, DefaultHtm, DefaultHtu);
        first.Should().NotBeNull();

        // Re-generate the access token with a fresh service instance that shares the same JTI store
        // is not possible; instead, rebuild an identical proof with the same jti and validate again
        // against the same service instance (same JTI HashSet).
        var proof2   = builder.Build(htm: DefaultHtm, htu: DefaultHtu, ath: ath, jti: fixedJti);
        var second   = await service.ValidateTokenAsync(accessToken, proof2, DefaultHtm, DefaultHtu);

        second.Should().BeNull();
    }

    [Fact]
    public async Task ValidateToken_DpopBound_WrongHtm_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var user          = MakeUser();

        var accessToken = await service.GenerateTokenAsync(user, builder.PublicJwkJson);
        var ath         = ComputeAth(accessToken);
        // Proof says GET, but validator expects POST
        var proof = builder.Build(htm: "GET", htu: DefaultHtu, ath: ath);

        var principal = await service.ValidateTokenAsync(accessToken, proof, DefaultHtm, DefaultHtu);

        principal.Should().BeNull();
    }

    [Fact]
    public async Task ValidateToken_DpopBound_WrongHtu_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var user          = MakeUser();

        var accessToken = await service.GenerateTokenAsync(user, builder.PublicJwkJson);
        var ath         = ComputeAth(accessToken);
        var proof       = builder.Build(htm: DefaultHtm, htu: "https://evil.example.com/steal", ath: ath);

        var principal = await service.ValidateTokenAsync(accessToken, proof, DefaultHtm, DefaultHtu);

        principal.Should().BeNull();
    }

    [Fact]
    public async Task ValidateToken_DpopBound_WrongKey_ReturnsNull()
    {
        // builder A is used to generate the access token (cnf bound to A's key).
        // builder B signs the proof and embeds B's public key — key mismatch.
        using var builderA = new DpopProofBuilder();
        using var builderB = new DpopProofBuilder();
        var service        = MakeService();
        var user           = MakeUser();

        var accessToken = await service.GenerateTokenAsync(user, builderA.PublicJwkJson);
        var ath         = ComputeAth(accessToken);
        // Proof is valid (correctly self-signed by B) but JWK thumbprint won't match cnf from A.
        var proof = builderB.Build(htm: DefaultHtm, htu: DefaultHtu, ath: ath);

        var principal = await service.ValidateTokenAsync(accessToken, proof, DefaultHtm, DefaultHtu);

        principal.Should().BeNull();
    }
}

// ---------------------------------------------------------------------------
// GetDpopKeyFromProof tests
// ---------------------------------------------------------------------------

public class TokenService_GetDpopKeyFromProof : TokenServiceTestBase
{
    private const string DefaultHtm = "POST";
    private const string DefaultHtu = "https://localhost/auth/make-assertion";

    [Fact]
    public async Task GetDpopKeyFromProof_ValidProof_ReturnsJwkJson()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var proof         = builder.Build(htm: DefaultHtm, htu: DefaultHtu);

        var result = await service.GetDpopKeyFromProof(proof, DefaultHtm, DefaultHtu);

        result.Should().NotBeNull();
        result.Should().Contain("kty");
    }

    [Fact]
    public async Task GetDpopKeyFromProof_WrongTyp_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var proof         = builder.Build(htm: DefaultHtm, htu: DefaultHtu, typ: "JWT");

        var result = await service.GetDpopKeyFromProof(proof, DefaultHtm, DefaultHtu);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetDpopKeyFromProof_MissingJwk_ReturnsNull()
    {
        // Build a token that has no jwk header by constructing it directly.
        using var ecKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var credentials = new SigningCredentials(new ECDsaSecurityKey(ecKey), SecurityAlgorithms.EcdsaSha256);
        var header      = new JwtHeader(credentials);
        header["typ"]   = "dpop+jwt";
        // Deliberately omit "jwk" from the header.
        var payload = new JwtPayload
        {
            ["htm"] = DefaultHtm,
            ["htu"] = DefaultHtu,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString()
        };
        var proof   = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
        var service = MakeService();

        var result = await service.GetDpopKeyFromProof(proof, DefaultHtm, DefaultHtu);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetDpopKeyFromProof_InvalidSignature_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var proof         = builder.BuildWithInvalidSignature(htm: DefaultHtm, htu: DefaultHtu);

        var result = await service.GetDpopKeyFromProof(proof, DefaultHtm, DefaultHtu);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetDpopKeyFromProof_WeakAlgorithm_ReturnsNull()
    {
        var service = MakeService();
        var proof   = DpopProofBuilder.BuildWithWeakAlgorithm(htm: DefaultHtm, htu: DefaultHtu);

        var result = await service.GetDpopKeyFromProof(proof, DefaultHtm, DefaultHtu);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetDpopKeyFromProof_MissingIat_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var proof         = builder.Build(htm: DefaultHtm, htu: DefaultHtu, omitIat: true);

        var result = await service.GetDpopKeyFromProof(proof, DefaultHtm, DefaultHtu);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetDpopKeyFromProof_StaleIat_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var staleIat      = DateTimeOffset.UtcNow.AddMinutes(-10);
        var proof         = builder.Build(htm: DefaultHtm, htu: DefaultHtu, iat: staleIat);

        var result = await service.GetDpopKeyFromProof(proof, DefaultHtm, DefaultHtu);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetDpopKeyFromProof_FutureIat_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var futureIat     = DateTimeOffset.UtcNow.AddMinutes(2);
        var proof         = builder.Build(htm: DefaultHtm, htu: DefaultHtu, iat: futureIat);

        var result = await service.GetDpopKeyFromProof(proof, DefaultHtm, DefaultHtu);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetDpopKeyFromProof_MissingJti_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var proof         = builder.Build(htm: DefaultHtm, htu: DefaultHtu, omitJti: true);

        var result = await service.GetDpopKeyFromProof(proof, DefaultHtm, DefaultHtu);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetDpopKeyFromProof_ReplayedJti_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var fixedJti      = Guid.NewGuid().ToString();

        var proof1  = builder.Build(htm: DefaultHtm, htu: DefaultHtu, jti: fixedJti);
        var first   = await service.GetDpopKeyFromProof(proof1, DefaultHtm, DefaultHtu);
        first.Should().NotBeNull();

        // Second proof uses the exact same jti — replay must be rejected.
        var proof2  = builder.Build(htm: DefaultHtm, htu: DefaultHtu, jti: fixedJti);
        var second  = await service.GetDpopKeyFromProof(proof2, DefaultHtm, DefaultHtu);
        second.Should().BeNull();
    }

    [Fact]
    public async Task GetDpopKeyFromProof_WrongHtm_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var proof         = builder.Build(htm: "GET", htu: DefaultHtu);

        var result = await service.GetDpopKeyFromProof(proof, DefaultHtm, DefaultHtu);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetDpopKeyFromProof_WrongHtu_ReturnsNull()
    {
        using var builder = new DpopProofBuilder();
        var service       = MakeService();
        var proof         = builder.Build(htm: DefaultHtm, htu: "https://evil.example.com/steal");

        var result = await service.GetDpopKeyFromProof(proof, DefaultHtm, DefaultHtu);

        result.Should().BeNull();
    }
}

// ---------------------------------------------------------------------------
// ComputeJwkThumbprint tests
// ---------------------------------------------------------------------------

public class TokenService_ComputeJwkThumbprint : TokenServiceTestBase
{
    [Fact]
    public void ComputeJwkThumbprint_SameKey_SameThumbprint()
    {
        using var builder = new DpopProofBuilder();
        var jwkJson       = builder.PublicJwkJson;

        var t1 = TokenService.ComputeJwkThumbprint(jwkJson);
        var t2 = TokenService.ComputeJwkThumbprint(jwkJson);

        t1.Should().NotBeNull();
        t1.Should().Be(t2);
    }

    [Fact]
    public void ComputeJwkThumbprint_DifferentKeys_DifferentThumbprints()
    {
        using var builder1 = new DpopProofBuilder();
        using var builder2 = new DpopProofBuilder();

        var t1 = TokenService.ComputeJwkThumbprint(builder1.PublicJwkJson);
        var t2 = TokenService.ComputeJwkThumbprint(builder2.PublicJwkJson);

        t1.Should().NotBeNull();
        t2.Should().NotBeNull();
        t1.Should().NotBe(t2);
    }

    [Fact]
    public void ComputeJwkThumbprint_InvalidJson_ReturnsNull()
    {
        var result = TokenService.ComputeJwkThumbprint("this is not valid json }{");

        result.Should().BeNull();
    }
}

// ---------------------------------------------------------------------------
// Session-revocation cutoff tests
//
// ValidateTokenAsync rejects any access token whose 'iat' predates the tenant-wide
// SessionsValidFrom cutoff (set by POST /tenants/{id}/revoke-sessions). Comparison is at
// whole-second granularity. These tokens are not DPoP-bound (no 'cnf'), so the DPoP path is
// skipped and only the revocation logic is exercised.
// ---------------------------------------------------------------------------

public class TokenService_SessionRevocation : TokenServiceTestBase
{
    [Fact]
    public async Task ValidateToken_IssuedBeforeTenantCutoff_ReturnsNull()
    {
        var tenant  = MakeTenant();
        var service = MakeService(tenant);
        var user    = MakeUser();

        var token = await service.GenerateTokenAsync(user);

        // Tenant-wide revocation happens AFTER the token was issued.
        tenant.SessionsValidFrom = DateTime.UtcNow.AddSeconds(5);

        var principal = await service.ValidateTokenAsync(token);

        principal.Should().BeNull();
    }

    [Fact]
    public async Task ValidateToken_TenantCutoffInPast_StillValid()
    {
        var tenant  = MakeTenant();
        var service = MakeService(tenant);
        var user    = MakeUser();

        var token = await service.GenerateTokenAsync(user);

        // A cutoff set before the token was issued must not reject it.
        tenant.SessionsValidFrom = DateTime.UtcNow.AddMinutes(-5);

        var principal = await service.ValidateTokenAsync(token);

        principal.Should().NotBeNull();
    }

    [Fact]
    public async Task ValidateToken_NoCutoff_StillValid()
    {
        var tenant  = MakeTenant(); // SessionsValidFrom defaults to DateTime.MinValue (no cutoff)
        var service = MakeService(tenant);
        var user    = MakeUser();

        var token = await service.GenerateTokenAsync(user);

        var principal = await service.ValidateTokenAsync(token);

        principal.Should().NotBeNull();
    }
}

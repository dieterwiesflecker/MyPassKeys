using System.Security.Claims;
using FluentAssertions;
using MyPassKeys.Tests.Helpers;
using Xunit;

namespace MyPassKeys.Tests;

// ---------------------------------------------------------------------------
// Cross-tenant token exchange (POST /auth/exchange): the subject token must
// validate against the HOME tenant that issued it, never the target tenant.
// These cover the TokenService pieces the endpoint builds on — explicit-tenant
// validation and the unvalidated claim/JWK readers.
// ---------------------------------------------------------------------------

public class ExchangeTokenTests : TokenServiceTestBase
{
    [Fact]
    public async Task ValidateTokenForTenant_AcceptsTokenIssuedByThatTenant()
    {
        var home = MakeTenant();
        var service = MakeService(home);
        var token = await service.GenerateTokenAsync(MakeUser());

        var principal = await service.ValidateTokenForTenantAsync(home, token);

        principal.Should().NotBeNull();
        principal!.FindFirst("tenant_id")!.Value.Should().Be(home.Id.ToString());
    }

    [Fact]
    public async Task ValidateTokenForTenant_RejectsTokenFromAnotherTenant()
    {
        var home = MakeTenant();
        var service = MakeService(home);
        var token = await service.GenerateTokenAsync(MakeUser());

        // Different keys AND different issuer/audience — either alone must fail it.
        var other = MakeTenant(issuer: "https://other.localhost", audience: "api://other.localhost");

        (await service.ValidateTokenForTenantAsync(other, token)).Should().BeNull();
    }

    [Fact]
    public async Task ReadTenantIdClaim_ReturnsIssuingTenantId()
    {
        var home = MakeTenant();
        var service = MakeService(home);
        var token = await service.GenerateTokenAsync(MakeUser());

        TokenService.ReadTenantIdClaim(token).Should().Be(home.Id);
    }

    [Fact]
    public void ReadTenantIdClaim_ReturnsNullForGarbage()
    {
        TokenService.ReadTenantIdClaim("not-a-jwt").Should().BeNull();
    }

    [Fact]
    public void ReadDpopJwk_ReturnsEmbeddedPublicKey()
    {
        using var builder = new DpopProofBuilder();
        var proof = builder.Build("POST", "https://test.localhost/auth/exchange");

        var jwk = TokenService.ReadDpopJwk(proof);

        jwk.Should().NotBeNullOrEmpty();
        TokenService.ComputeJwkThumbprint(jwk!)
            .Should().Be(TokenService.ComputeJwkThumbprint(builder.PublicJwkJson));
    }

    [Fact]
    public void ReadDpopJwk_ReturnsNullForGarbage()
    {
        TokenService.ReadDpopJwk("not-a-jwt").Should().BeNull();
    }
}

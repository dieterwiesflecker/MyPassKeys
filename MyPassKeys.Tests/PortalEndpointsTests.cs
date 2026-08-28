using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Http.HttpResults;
using Moq;
using Xunit;

namespace MyPassKeys.Tests;

// ---------------------------------------------------------------------------
// Self-service portal authorization (role/membership model)
//
// PortalEndpoints.AuthorizeTenantAsync gates tenant administration by the caller's 'tid' JWT
// claim (must point to the management tenant) and by the caller's membership role in the target
// tenant. Non-members get 404 (existence hidden); useradmin-only members on a tenantadmin-
// required endpoint get 403.
// ---------------------------------------------------------------------------

public class PortalEndpointsTests
{
    private static readonly Guid ManagementTenantId = Guid.NewGuid();

    private static ClaimsPrincipal ManagementPrincipal(Guid? userId, string? email = null)
    {
        var claims = new List<Claim>();
        if (userId.HasValue) claims.Add(new Claim(ClaimTypes.NameIdentifier, userId.Value.ToString()));
        if (email != null) claims.Add(new Claim(ClaimTypes.Name, email));
        claims.Add(new Claim("tenant_id", ManagementTenantId.ToString()));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    private static Mock<IFido2DbService> DbWith(Tenant target, Fido2AppUser? membership)
    {
        var db = new Mock<IFido2DbService>();
        db.Setup(s => s.GetTenantByIdAsync(ManagementTenantId))
            .ReturnsAsync(new Tenant { Id = ManagementTenantId, IsManagementTenant = true });
        db.Setup(s => s.GetTenantByIdAsync(target.Id)).ReturnsAsync(target);
        db.Setup(s => s.GetUserByUsernameForTenantAsync(target.Id, It.IsAny<string>())).ReturnsAsync(membership);
        return db;
    }

    [Fact]
    public async Task TenantAdminMember_IsAuthorized()
    {
        var target = new Tenant { Id = Guid.NewGuid() };
        var membership = new Fido2AppUser { Username = "a@x.com", Roles = [BuiltInTenantRoles.TenantAdmin] };
        var db = DbWith(target, membership);

        var (_, _, error) = await PortalEndpoints.AuthorizeTenantAsync(
            target.Id, ManagementPrincipal(Guid.NewGuid(), "a@x.com"),
            db.Object, tenantAdminRequired: true);

        error.Should().BeNull();
    }

    [Fact]
    public async Task UserAdminMember_AllowedForUserAdmin_ForbiddenForTenantAdmin()
    {
        var target = new Tenant { Id = Guid.NewGuid() };
        var membership = new Fido2AppUser { Username = "u@x.com", Roles = [BuiltInTenantRoles.UserAdmin] };

        var (_, _, okError) = await PortalEndpoints.AuthorizeTenantAsync(
            target.Id, ManagementPrincipal(Guid.NewGuid(), "u@x.com"),
            DbWith(target, membership).Object, tenantAdminRequired: false);
        okError.Should().BeNull();

        var (_, _, forbidden) = await PortalEndpoints.AuthorizeTenantAsync(
            target.Id, ManagementPrincipal(Guid.NewGuid(), "u@x.com"),
            DbWith(target, membership).Object, tenantAdminRequired: true);
        forbidden.Should().BeOfType<ForbidHttpResult>();
    }

    [Fact]
    public async Task NonMember_GetsNotFound()
    {
        var target = new Tenant { Id = Guid.NewGuid() };
        var db = DbWith(target, membership: null);

        var (_, _, error) = await PortalEndpoints.AuthorizeTenantAsync(
            target.Id, ManagementPrincipal(Guid.NewGuid(), "nobody@x.com"),
            db.Object, tenantAdminRequired: false);

        error.Should().BeOfType<NotFound>();
    }

    [Fact]
    public async Task NonManagementToken_IsRejected()
    {
        var target = new Tenant { Id = Guid.NewGuid() };
        var otherTenantId = Guid.NewGuid();
        var db = new Mock<IFido2DbService>();
        db.Setup(s => s.GetTenantByIdAsync(otherTenantId))
            .ReturnsAsync(new Tenant { Id = otherTenantId, IsManagementTenant = false });

        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new Claim("tenant_id", otherTenantId.ToString()),
        ], "test"));

        var (_, _, error) = await PortalEndpoints.AuthorizeTenantAsync(
            target.Id, principal, db.Object, tenantAdminRequired: false);

        error.Should().BeOfType<ProblemHttpResult>().Which.StatusCode.Should().Be(403);
        db.Verify(s => s.GetTenantByIdAsync(target.Id), Times.Never);
    }

    [Fact]
    public async Task MissingTidClaim_IsRejected()
    {
        var db = new Mock<IFido2DbService>();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
        ], "test"));

        var (_, _, error) = await PortalEndpoints.AuthorizeTenantAsync(
            Guid.NewGuid(), principal, db.Object, tenantAdminRequired: false);

        error.Should().BeOfType<ProblemHttpResult>().Which.StatusCode.Should().Be(403);
    }

    [Fact]
    public async Task Unauthenticated_IsRejected()
    {
        var db = new Mock<IFido2DbService>();
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        var (_, _, error) = await PortalEndpoints.AuthorizeTenantAsync(
            Guid.NewGuid(), principal, db.Object, tenantAdminRequired: false);

        error.Should().BeOfType<UnauthorizedHttpResult>();
    }
}

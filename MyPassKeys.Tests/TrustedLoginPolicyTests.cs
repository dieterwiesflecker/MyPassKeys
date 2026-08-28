using FluentAssertions;
using Xunit;

namespace MyPassKeys.Tests;

// ---------------------------------------------------------------------------
// Trusted cross-tenant login (Tenant.TrustedCredentialTenantIds): whether a
// user unknown to the target tenant may be provisioned just-in-time after a
// successful assertion against a trusted tenant's credential. Mirrors the
// self-registration policy; an existing local user logs in regardless of mode
// (that path never consults CanJitProvision).
// ---------------------------------------------------------------------------

public class TrustedLoginPolicyTests
{
    private static Tenant Tenant(string mode, string[]? domains = null) => new()
    {
        RegistrationMode = mode,
        AllowedEmailDomains = domains ?? []
    };

    [Fact]
    public void Open_AllowsJitProvisioning()
    {
        RegistrationPolicy.CanJitProvision(Tenant(RegistrationModes.Open), "jane@anything.com")
            .Should().BeTrue();
    }

    [Fact]
    public void InviteOnly_NeverAllowsJitProvisioning()
    {
        // The pre-created user IS the invite; auto-creating one would bypass it.
        RegistrationPolicy.CanJitProvision(Tenant(RegistrationModes.InviteOnly), "jane@x.com")
            .Should().BeFalse();
    }

    [Fact]
    public void DomainAllowlist_AllowsMatchingDomain()
    {
        var t = Tenant(RegistrationModes.DomainAllowlist, ["acme.com"]);
        RegistrationPolicy.CanJitProvision(t, "jane@acme.com").Should().BeTrue();
    }

    [Fact]
    public void DomainAllowlist_RejectsNonMatchingDomain()
    {
        var t = Tenant(RegistrationModes.DomainAllowlist, ["acme.com"]);
        RegistrationPolicy.CanJitProvision(t, "jane@evil.com").Should().BeFalse();
    }

    [Fact]
    public void DomainAllowlist_WildcardMatchesSubdomainOnly()
    {
        var t = Tenant(RegistrationModes.DomainAllowlist, ["*.acme.com"]);
        RegistrationPolicy.CanJitProvision(t, "jane@sub.acme.com").Should().BeTrue();
        RegistrationPolicy.CanJitProvision(t, "jane@acme.com").Should().BeFalse();
    }

    [Fact]
    public void UnknownMode_FailsClosed()
    {
        RegistrationPolicy.CanJitProvision(Tenant("something-new"), "jane@x.com")
            .Should().BeFalse();
    }
}

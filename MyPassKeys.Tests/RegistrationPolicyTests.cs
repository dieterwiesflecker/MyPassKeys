using FluentAssertions;
using Xunit;

namespace MyPassKeys.Tests;

// ---------------------------------------------------------------------------
// Registration policy: which roles a self-registrant receives, plus the
// normalization rules that keep stored default/domain roles aligned with the
// (lower-cased) role catalog. Catalog-existence filtering is applied at the
// registration endpoint, not here, so these tests cover the pure resolution.
// ---------------------------------------------------------------------------

public class RegistrationPolicyTests
{
    private static Tenant Tenant(string mode, string[]? domains = null,
        string[]? defaultRoles = null, Dictionary<string, string[]>? domainRoles = null) => new()
    {
        RegistrationMode = mode,
        AllowedEmailDomains = domains ?? [],
        DefaultRoles = defaultRoles ?? [],
        DomainRoles = domainRoles ?? new()
    };

    [Fact]
    public void Open_GrantsDefaultRoles()
    {
        var t = Tenant(RegistrationModes.Open, defaultRoles: ["member", "editor"]);
        RegistrationPolicy.RolesForRegistration(t, "jane@anything.com")
            .Should().BeEquivalentTo("member", "editor");
    }

    [Fact]
    public void InviteOnly_GrantsNothing()
    {
        var t = Tenant(RegistrationModes.InviteOnly, defaultRoles: ["member"]);
        RegistrationPolicy.RolesForRegistration(t, "jane@x.com").Should().BeEmpty();
    }

    [Fact]
    public void DomainAllowlist_GrantsRolesForMatchingExactDomain()
    {
        var t = Tenant(RegistrationModes.DomainAllowlist,
            domains: ["acme.com"],
            domainRoles: new() { ["acme.com"] = ["member"] });
        RegistrationPolicy.RolesForRegistration(t, "jane@acme.com")
            .Should().BeEquivalentTo("member");
    }

    [Fact]
    public void DomainAllowlist_UnionsRolesWhenApexAndWildcardBothMatch()
    {
        var t = Tenant(RegistrationModes.DomainAllowlist,
            domains: ["acme.com", "*.acme.com"],
            domainRoles: new()
            {
                ["acme.com"] = ["member"],
                ["*.acme.com"] = ["member", "editor"]
            });
        // sub.acme.com matches only the wildcard; the apex entry does not match a subdomain.
        RegistrationPolicy.RolesForRegistration(t, "jane@sub.acme.com")
            .Should().BeEquivalentTo("member", "editor");
    }

    [Fact]
    public void DomainAllowlist_NoRolesWhenDomainHasNoMapping()
    {
        var t = Tenant(RegistrationModes.DomainAllowlist,
            domains: ["acme.com"],
            domainRoles: new());
        RegistrationPolicy.RolesForRegistration(t, "jane@acme.com").Should().BeEmpty();
    }

    [Theory]
    [InlineData("acme.com", "acme.com", true)]
    [InlineData("sub.acme.com", "acme.com", false)]    // apex entry doesn't match subdomain
    [InlineData("sub.acme.com", "*.acme.com", true)]
    [InlineData("acme.com", "*.acme.com", false)]      // wildcard doesn't match the apex
    [InlineData("a.b.acme.com", "*.acme.com", true)]   // any depth
    public void EntryMatches_Cases(string domain, string entry, bool expected)
    {
        RegistrationPolicy.EntryMatches(domain, entry).Should().Be(expected);
    }

    [Fact]
    public void NormalizeRoles_TrimsLowercasesDedupesAndDropsEmpties()
    {
        RegistrationPolicy.NormalizeRoles(["  Member ", "EDITOR", "member", "", "  "])
            .Should().BeEquivalentTo("member", "editor");
    }

    [Fact]
    public void NormalizeDomainRoles_DropsKeysNotInAllowedDomainsAndEmptyRoleLists()
    {
        var input = new Dictionary<string, string[]>
        {
            ["@Acme.com"] = ["Member"],   // leading @ stripped, lower-cased
            ["other.com"] = ["member"],   // not in allowlist → dropped
            ["acme.com"] = [],            // empty role list → dropped (key duplicate after normalize)
            ["*.acme.com"] = ["  ", ""]   // becomes empty → dropped
        };
        var result = RegistrationPolicy.NormalizeDomainRoles(input, ["acme.com", "*.acme.com"]);

        result.Should().ContainKey("acme.com");
        result["acme.com"].Should().BeEquivalentTo("member");
        result.Should().NotContainKey("other.com");
        result.Should().NotContainKey("*.acme.com");
    }
}

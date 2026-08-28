using FluentAssertions;
using Xunit;

namespace MyPassKeys.Tests;

// ---------------------------------------------------------------------------
// Username normalization
//
// Usernames must be lower-cased and trimmed everywhere. Storage normalization is enforced by
// Fido2AppUser.Username's setter (so it also applies to Marten deserialization); lookups and
// Redis challenge keys normalize via the shared StringExtensions.NormalizeUsername helper.
// ---------------------------------------------------------------------------

public class UsernameNormalizationTests
{
    [Theory]
    [InlineData("Alice@Example.COM", "alice@example.com")]
    [InlineData("  bob@example.com  ", "bob@example.com")]
    [InlineData("CAROL@EXAMPLE.COM", "carol@example.com")]
    public void Username_IsNormalizedOnAssignment(string input, string expected)
    {
        var user = new Fido2AppUser { Username = input };
        user.Username.Should().Be(expected);
    }

    [Theory]
    [InlineData("Alice@Example.COM", "alice@example.com")]
    [InlineData("  bob@example.com  ", "bob@example.com")]
    [InlineData(null, "")]
    [InlineData("   ", "")]
    public void NormalizeUsername_TrimsAndLowercases(string? input, string expected)
    {
        input.NormalizeUsername().Should().Be(expected);
    }
}

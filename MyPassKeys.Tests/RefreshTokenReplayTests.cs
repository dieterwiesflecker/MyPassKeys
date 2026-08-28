using FluentAssertions;
using Xunit;

namespace MyPassKeys.Tests;

// ---------------------------------------------------------------------------
// Refresh-token replay decision
//
// When an already-rotated (revoked) refresh token is presented again, Fido2Endpoints decides
// whether it is a benign concurrent-tab race (reject just this request) or a genuine stolen-token
// replay (revoke the user's whole token family). The decision is age-based: reuse within the
// grace window of rotation is treated as a race; outside it, as a compromise.
// ---------------------------------------------------------------------------

public class RefreshTokenReplayTests
{
    private static readonly System.TimeSpan Grace = Fido2Endpoints.RefreshReplayGraceWindow;

    [Fact]
    public void ReusedWithinGraceWindow_IsNotTreatedAsReplay()
    {
        var now = System.DateTime.UtcNow;
        var revokedAt = now - (Grace - System.TimeSpan.FromSeconds(5)); // 5s inside the window

        Fido2Endpoints.IsReplayOutsideGraceWindow(revokedAt, now).Should().BeFalse();
    }

    [Fact]
    public void ReusedAfterGraceWindow_IsTreatedAsReplay()
    {
        var now = System.DateTime.UtcNow;
        var revokedAt = now - (Grace + System.TimeSpan.FromSeconds(5)); // 5s past the window

        Fido2Endpoints.IsReplayOutsideGraceWindow(revokedAt, now).Should().BeTrue();
    }

    [Fact]
    public void NullRevokedAt_FailsSafeToBenign()
    {
        // Legacy tokens rotated before RevokedAt existed have no timestamp; they must not trigger
        // family-wide revocation.
        var now = System.DateTime.UtcNow;

        Fido2Endpoints.IsReplayOutsideGraceWindow(null, now).Should().BeFalse();
    }
}

using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using StackExchange.Redis;
using Xunit;

namespace MyPassKeys.Tests;

public class VersionAnchorTests
{
    private static readonly HmacDocumentIntegrity Integrity =
        new(Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="));

    private static Fido2AppUser MakeUser() => new()
    {
        Id = Guid.NewGuid(),
        TenantId = Guid.NewGuid(),
        Username = "user@example.com",
        Roles = ["tenantadmin"]
    };

    /// <summary>Dictionary-backed IConnectionMultiplexer covering the ops the anchor uses.</summary>
    private static (IConnectionMultiplexer Redis, Dictionary<string, string> Store) BuildInMemoryRedis()
    {
        var store = new Dictionary<string, string>();
        var db = new Mock<IDatabase>();

        db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .Returns<RedisKey, CommandFlags>((key, _) =>
                Task.FromResult(store.TryGetValue(key.ToString(), out var value)
                    ? (RedisValue)value
                    : RedisValue.Null));

        db.Setup(d => d.StringSetAsync(
                It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(),
                It.IsAny<When>()))
            .Returns<RedisKey, RedisValue, TimeSpan?, When>(
                (key, value, _, _) => { store[key.ToString()] = value.ToString(); return Task.FromResult(true); });

        db.Setup(d => d.StringSetAsync(
                It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(),
                It.IsAny<When>(), It.IsAny<CommandFlags>()))
            .Returns<RedisKey, RedisValue, TimeSpan?, When, CommandFlags>(
                (key, value, _, _, _) => { store[key.ToString()] = value.ToString(); return Task.FromResult(true); });

        db.Setup(d => d.StringSetAsync(
                It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(),
                It.IsAny<bool>(), It.IsAny<When>(), It.IsAny<CommandFlags>()))
            .Returns<RedisKey, RedisValue, TimeSpan?, bool, When, CommandFlags>(
                (key, value, _, _, _, _) => { store[key.ToString()] = value.ToString(); return Task.FromResult(true); });

        var multiplexer = new Mock<IConnectionMultiplexer>();
        multiplexer.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object?>())).Returns(db.Object);
        return (multiplexer.Object, store);
    }

    private static RedisVersionAnchor MakeAnchor(IConnectionMultiplexer redis) =>
        new(redis, NullLogger<RedisVersionAnchor>.Instance);

    [Fact]
    public void Seal_increments_the_version()
    {
        var user = MakeUser();
        user.Version.Should().Be(0);

        Integrity.Seal(user);
        user.Version.Should().Be(1);

        Integrity.Seal(user);
        user.Version.Should().Be(2);
    }

    [Fact]
    public void Version_is_covered_by_the_seal()
    {
        // Restoring an old version number onto a newer sealed doc must break the seal itself —
        // the attacker cannot decouple version and seal.
        var user = MakeUser();
        Integrity.Seal(user);
        user.Version = 99;

        var verify = () => Integrity.Verify(user);
        verify.Should().Throw<DocumentTamperedException>();
    }

    [Fact]
    public async Task Missing_anchor_is_adopted()
    {
        var (redis, store) = BuildInMemoryRedis();
        var anchor = MakeAnchor(redis);
        var user = MakeUser();
        Integrity.Seal(user);

        await anchor.CheckAsync(user); // no throw

        store[$"docver:user:{user.Id}"].Should().Be("1");
    }

    [Fact]
    public async Task Rolled_back_document_is_rejected()
    {
        var (redis, _) = BuildInMemoryRedis();
        var anchor = MakeAnchor(redis);

        // Generation 1 is validly sealed; keep a copy (the attacker's snapshot).
        var user = MakeUser();
        Integrity.Seal(user);
        var oldVersion = user.Version;
        var oldSeal = user.Integrity;

        // The app writes generation 2 and anchors it.
        user.Roles.Clear(); // admin role revoked
        Integrity.Seal(user);
        await anchor.RecordAsync(user);

        // Attacker restores the old (validly sealed) copy.
        user.Roles.Add("tenantadmin");
        user.Version = oldVersion;
        user.Integrity = oldSeal;
        Integrity.Verify(user); // the seal alone cannot catch this…

        var check = () => anchor.CheckAsync(user); // …the anchor does
        await check.Should().ThrowAsync<DocumentTamperedException>()
            .WithMessage("*older copy was restored*");
    }

    [Fact]
    public async Task Anchor_behind_the_document_is_repaired_upward()
    {
        // Models a crash between SaveChanges and RecordAsync: stored version is ahead.
        var (redis, store) = BuildInMemoryRedis();
        var anchor = MakeAnchor(redis);
        var user = MakeUser();
        Integrity.Seal(user);
        await anchor.RecordAsync(user);

        Integrity.Seal(user); // generation 2 persisted, but never anchored

        await anchor.CheckAsync(user); // no throw

        store[$"docver:user:{user.Id}"].Should().Be("2");
    }

    [Fact]
    public async Task Matching_anchor_passes()
    {
        var (redis, _) = BuildInMemoryRedis();
        var anchor = MakeAnchor(redis);
        var user = MakeUser();
        Integrity.Seal(user);
        await anchor.RecordAsync(user);

        var check = () => anchor.CheckAsync(user);
        await check.Should().NotThrowAsync();
    }
}

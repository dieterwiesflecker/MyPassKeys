using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace MyPassKeys.Tests;

public class KeyProtectorTests
{
    private static readonly byte[] KekA = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
    private static readonly byte[] KekB = Convert.FromBase64String("Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=");

    private static JsonElement SamplePrivateJwk() =>
        JsonSerializer.SerializeToElement(new
        {
            kty = "EC", crv = "P-256", x = "xxx", y = "yyy", d = "secret-scalar", kid = "kid-1"
        });

    [Fact]
    public void Protect_then_Unprotect_roundtrips_the_private_jwk()
    {
        var protector = new AesGcmKeyProtector(KekA);
        var jwk = SamplePrivateJwk();

        var stored = protector.Protect(jwk, "kid-1");
        var recovered = protector.Unprotect(stored, "kid-1");

        recovered.GetRawText().Should().Be(jwk.GetRawText());
    }

    [Fact]
    public void Protected_blob_does_not_contain_the_private_scalar()
    {
        var protector = new AesGcmKeyProtector(KekA);

        var stored = protector.Protect(SamplePrivateJwk(), "kid-1");

        stored.TryGetProperty("d", out _).Should().BeFalse();
        stored.GetRawText().Should().NotContain("secret-scalar");
        stored.GetProperty("enc").GetString().Should().Be("A256GCM");
        AesGcmKeyProtector.IsEncrypted(stored).Should().BeTrue();
    }

    [Fact]
    public void Unprotect_passes_legacy_plaintext_through_unchanged()
    {
        var protector = new AesGcmKeyProtector(KekA);
        var jwk = SamplePrivateJwk();

        // Pre-migration documents (and stale Redis cache entries) still hold the plaintext JWK.
        var recovered = protector.Unprotect(jwk, "kid-1");

        recovered.GetRawText().Should().Be(jwk.GetRawText());
        AesGcmKeyProtector.IsEncrypted(jwk).Should().BeFalse();
        protector.IsProtectedWithCurrentKey(jwk).Should().BeFalse();
    }

    [Fact]
    public void Unprotect_with_wrong_kid_fails_the_integrity_check()
    {
        // The kid is bound as AAD, so a ciphertext moved onto another key entry must not decrypt.
        var protector = new AesGcmKeyProtector(KekA);
        var stored = protector.Protect(SamplePrivateJwk(), "kid-1");

        var act = () => protector.Unprotect(stored, "kid-2");

        act.Should().Throw<InvalidOperationException>().WithMessage("*integrity*");
    }

    [Fact]
    public void Unprotect_with_tampered_ciphertext_fails_the_integrity_check()
    {
        var protector = new AesGcmKeyProtector(KekA);
        var stored = protector.Protect(SamplePrivateJwk(), "kid-1");

        var ct = stored.GetProperty("ct").GetBytesFromBase64();
        ct[0] ^= 0xFF;
        var tampered = JsonSerializer.SerializeToElement(new
        {
            enc = stored.GetProperty("enc").GetString(),
            kek = stored.GetProperty("kek").GetString(),
            iv = stored.GetProperty("iv").GetString(),
            ct = Convert.ToBase64String(ct),
            tag = stored.GetProperty("tag").GetString()
        });

        var act = () => protector.Unprotect(tampered, "kid-1");

        act.Should().Throw<InvalidOperationException>().WithMessage("*integrity*");
    }

    [Fact]
    public void Unprotect_under_unknown_kek_reports_the_kek_id()
    {
        var protectorA = new AesGcmKeyProtector(KekA);
        var protectorB = new AesGcmKeyProtector(KekB);
        var stored = protectorA.Protect(SamplePrivateJwk(), "kid-1");

        var act = () => protectorB.Unprotect(stored, "kid-1");

        act.Should().Throw<InvalidOperationException>().WithMessage("*unknown key-encryption key*");
    }

    [Fact]
    public void Previous_kek_still_decrypts_and_is_flagged_for_reencryption()
    {
        // KEK rotation: B becomes current, A moves to PreviousKeyEncryptionKeys. Old blobs must
        // decrypt, be reported as not-current (so the startup migration re-encrypts them), and
        // the re-encrypted blob must then be current.
        var oldProtector = new AesGcmKeyProtector(KekA);
        var rotated = new AesGcmKeyProtector(KekB, [KekA]);
        var storedUnderA = oldProtector.Protect(SamplePrivateJwk(), "kid-1");

        rotated.IsProtectedWithCurrentKey(storedUnderA).Should().BeFalse();
        var recovered = rotated.Unprotect(storedUnderA, "kid-1");
        recovered.GetRawText().Should().Be(SamplePrivateJwk().GetRawText());

        var reEncrypted = rotated.Protect(recovered, "kid-1");
        rotated.IsProtectedWithCurrentKey(reEncrypted).Should().BeTrue();
        rotated.Unprotect(reEncrypted, "kid-1").GetRawText().Should().Be(SamplePrivateJwk().GetRawText());
    }

    [Fact]
    public void FromConfiguration_throws_when_kek_is_missing()
    {
        var config = new ConfigurationBuilder().Build();

        var act = () => AesGcmKeyProtector.FromConfiguration(config);

        act.Should().Throw<InvalidOperationException>().WithMessage("*MyPassKeys:KeyEncryptionKey*");
    }

    [Fact]
    public void FromConfiguration_throws_when_kek_is_not_32_bytes()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["MyPassKeys:KeyEncryptionKey"] = Convert.ToBase64String(new byte[16])
            })
            .Build();

        var act = () => AesGcmKeyProtector.FromConfiguration(config);

        act.Should().Throw<InvalidOperationException>().WithMessage("*32*");
    }

    [Fact]
    public void FromConfiguration_loads_previous_keks()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["MyPassKeys:KeyEncryptionKey"] = Convert.ToBase64String(KekB),
                ["MyPassKeys:PreviousKeyEncryptionKeys:0"] = Convert.ToBase64String(KekA)
            })
            .Build();

        var protector = AesGcmKeyProtector.FromConfiguration(config);
        var storedUnderA = new AesGcmKeyProtector(KekA).Protect(SamplePrivateJwk(), "kid-1");

        protector.Unprotect(storedUnderA, "kid-1").GetRawText().Should().Be(SamplePrivateJwk().GetRawText());
        protector.IsProtectedWithCurrentKey(storedUnderA).Should().BeFalse();
    }

    [Fact]
    public void CreateKeyEntry_stores_the_private_key_encrypted()
    {
        var protector = new AesGcmKeyProtector(KekA);

        var entry = TenantEndpoints.CreateKeyEntry(protector);

        AesGcmKeyProtector.IsEncrypted(entry.PrivateKey).Should().BeTrue();
        protector.IsProtectedWithCurrentKey(entry.PrivateKey).Should().BeTrue();
        entry.PrivateKey.GetRawText().Should().NotContain("\"d\"");

        // The public half stays plaintext for JWKS, and the decrypted private JWK matches it.
        entry.PublicKey.GetProperty("kty").GetString().Should().Be("EC");
        var privateJwk = protector.Unprotect(entry.PrivateKey, entry.Kid);
        privateJwk.GetProperty("d").GetString().Should().NotBeNullOrEmpty();
        privateJwk.GetProperty("x").GetString().Should().Be(entry.PublicKey.GetProperty("x").GetString());
    }
}

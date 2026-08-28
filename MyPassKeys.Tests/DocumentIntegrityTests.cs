using FluentAssertions;
using Xunit;

namespace MyPassKeys.Tests;

public class DocumentIntegrityTests
{
    private static readonly byte[] KekA = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
    private static readonly byte[] KekB = Convert.FromBase64String("Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=");

    private static readonly HmacDocumentIntegrity Integrity = new(KekA);

    private static Fido2AppUser MakeUser() => new()
    {
        Id = Guid.NewGuid(),
        TenantId = Guid.NewGuid(),
        Username = "user@example.com",
        DisplayName = "User",
        Roles = ["app"]
    };

    private static Fido2StoredCredential MakeCredential() => new()
    {
        Id = "cred-1",
        TenantId = Guid.NewGuid(),
        UserId = Guid.NewGuid(),
        CredentialId = [1, 2, 3],
        PublicKey = [4, 5, 6],
        CredType = "public-key",
        Transports = ["internal"],
        AttestationObject = [7],
        ClientDataJson = [8]
    };

    private static TenantGroup MakeGroup() => new()
    {
        Id = Guid.NewGuid(),
        TenantId = Guid.NewGuid(),
        Name = "devs",
        Roles = ["app"],
        MemberUserIds = [Guid.NewGuid()]
    };

    private static Fido2RefreshToken MakeRefreshToken() => new()
    {
        Id = Guid.NewGuid(),
        TenantId = Guid.NewGuid(),
        UserId = Guid.NewGuid(),
        Token = "hashed-token",
        Expiry = DateTime.UtcNow.AddHours(1),
        DpopJkt = "jkt-value"
    };

    // -----------------------------------------------------------------------
    // Seal + verify roundtrips
    // -----------------------------------------------------------------------

    [Fact]
    public void Sealed_documents_verify()
    {
        var docs = new object[]
        {
            MakeUser(),
            MakeCredential(),
            MakeGroup(),
            MakeRefreshToken(),
            new TenantRole { TenantId = Guid.NewGuid(), Name = "custom", Permissions = ["users:read"] },
            new Tenant { Id = Guid.NewGuid(), ServerName = "App", AllowedOrigins = ["https://a.example"] }
        };

        foreach (var doc in docs)
        {
            Integrity.Seal(doc);
            Integrity.HasSeal(doc).Should().BeTrue();
            Integrity.IsSealedWithCurrentKey(doc).Should().BeTrue();
            var verify = () => Integrity.Verify(doc);
            verify.Should().NotThrow();
        }
    }

    [Fact]
    public void Unsealed_document_fails_verification()
    {
        var verify = () => Integrity.Verify(MakeUser());
        verify.Should().Throw<DocumentTamperedException>().WithMessage("*no integrity seal*");
    }

    // -----------------------------------------------------------------------
    // Tampering with protected fields is detected
    // -----------------------------------------------------------------------

    [Fact]
    public void Escalating_user_roles_is_detected()
    {
        var user = MakeUser();
        Integrity.Seal(user);
        user.Roles.Add("tenantadmin");

        var verify = () => Integrity.Verify(user);
        verify.Should().Throw<DocumentTamperedException>().WithMessage("*integrity check*");
    }

    [Fact]
    public void Escalating_role_permissions_is_detected()
    {
        var role = new TenantRole { TenantId = Guid.NewGuid(), Name = "custom", Permissions = ["users:read"] };
        Integrity.Seal(role);
        role.Permissions.Add("roles:manage");

        var verify = () => Integrity.Verify(role);
        verify.Should().Throw<DocumentTamperedException>();
    }

    [Fact]
    public void Adding_a_group_member_is_detected()
    {
        var group = MakeGroup();
        Integrity.Seal(group);
        group.MemberUserIds.Add(Guid.NewGuid());

        var verify = () => Integrity.Verify(group);
        verify.Should().Throw<DocumentTamperedException>();
    }

    [Fact]
    public void Attaching_a_role_to_a_group_is_detected()
    {
        var group = MakeGroup();
        Integrity.Seal(group);
        group.Roles.Add("tenantadmin");

        var verify = () => Integrity.Verify(group);
        verify.Should().Throw<DocumentTamperedException>();
    }

    [Fact]
    public void Rehoming_a_credential_to_another_user_is_detected()
    {
        // A credential's UserId/PublicKey are init-only in C#, but a direct DB write has no such
        // constraint — model the swap by sealing one credential and moving its seal onto a
        // second credential that differs only in UserId.
        var tenantId = Guid.NewGuid();
        var original = MakeCredential();
        original.TenantId = tenantId;
        Integrity.Seal(original);

        var swapped = new Fido2StoredCredential
        {
            Id = original.Id,
            TenantId = tenantId,
            UserId = Guid.NewGuid(), // attacker points the victim's credential at another identity
            CredentialId = original.CredentialId,
            PublicKey = original.PublicKey,
            CredType = original.CredType,
            Transports = original.Transports,
            AttestationObject = original.AttestationObject,
            ClientDataJson = original.ClientDataJson,
            Integrity = original.Integrity
        };

        var verify = () => Integrity.Verify(swapped);
        verify.Should().Throw<DocumentTamperedException>();
    }

    [Fact]
    public void Flipping_management_flag_or_trust_links_is_detected()
    {
        var tenant = new Tenant { Id = Guid.NewGuid(), ServerName = "App" };
        Integrity.Seal(tenant);

        tenant.IsManagementTenant = true;
        var verifyFlag = () => Integrity.Verify(tenant);
        verifyFlag.Should().Throw<DocumentTamperedException>();

        tenant.IsManagementTenant = false;
        tenant.TrustedCredentialTenantIds = [Guid.NewGuid()];
        var verifyTrust = () => Integrity.Verify(tenant);
        verifyTrust.Should().Throw<DocumentTamperedException>();
    }

    [Fact]
    public void Unrevoking_a_refresh_token_is_detected()
    {
        var token = MakeRefreshToken();
        token.IsRevoked = true;
        token.RevokedAt = DateTime.UtcNow;
        Integrity.Seal(token);

        token.IsRevoked = false;
        token.RevokedAt = null;

        var verify = () => Integrity.Verify(token);
        verify.Should().Throw<DocumentTamperedException>();
    }

    [Fact]
    public void Cosmetic_fields_are_not_sealed()
    {
        // DisplayName is deliberately outside the seal — verify editing it doesn't invalidate.
        var role = new TenantRole { TenantId = Guid.NewGuid(), Name = "custom", Permissions = ["users:read"] };
        Integrity.Seal(role);
        role.DisplayName = "Renamed";
        role.UpdatedAt = DateTime.UtcNow.AddMinutes(5);

        var verify = () => Integrity.Verify(role);
        verify.Should().NotThrow();
    }

    // -----------------------------------------------------------------------
    // Seal transplant / key handling
    // -----------------------------------------------------------------------

    [Fact]
    public void Seal_cannot_be_transplanted_between_documents()
    {
        var alice = MakeUser();
        Integrity.Seal(alice);

        var mallory = MakeUser();
        mallory.Integrity = alice.Integrity;

        var verify = () => Integrity.Verify(mallory);
        verify.Should().Throw<DocumentTamperedException>();
    }

    [Fact]
    public void Seal_made_with_unknown_key_is_rejected()
    {
        var user = MakeUser();
        new HmacDocumentIntegrity(KekB).Seal(user);

        var verify = () => Integrity.Verify(user);
        verify.Should().Throw<DocumentTamperedException>().WithMessage("*unrecognized*");
    }

    [Fact]
    public void Previous_kek_seal_verifies_and_is_flagged_for_resealing()
    {
        var user = MakeUser();
        new HmacDocumentIntegrity(KekA).Seal(user);

        var rotated = new HmacDocumentIntegrity(KekB, [KekA]);
        var verify = () => rotated.Verify(user);
        verify.Should().NotThrow();
        rotated.IsSealedWithCurrentKey(user).Should().BeFalse();

        rotated.Seal(user);
        rotated.IsSealedWithCurrentKey(user).Should().BeTrue();
    }

    [Fact]
    public void Mac_key_is_independent_of_the_encryption_key()
    {
        // The HMAC key is HKDF-derived from the KEK — sealing must not equal raw-KEK HMAC usage
        // elsewhere. Sanity check: two different KEKs produce different seals for the same doc.
        var user = MakeUser();
        new HmacDocumentIntegrity(KekA).Seal(user);
        var sealA = user.Integrity;
        new HmacDocumentIntegrity(KekB).Seal(user);
        user.Integrity.Should().NotBe(sealA);
    }

    [Fact]
    public void Order_of_list_entries_does_not_matter()
    {
        // Collections are canonicalized sorted: storage-level reordering is not tampering.
        var user = MakeUser();
        user.Roles.Add("useradmin");
        Integrity.Seal(user);

        user.Roles.Reverse();

        var verify = () => Integrity.Verify(user);
        verify.Should().NotThrow();
    }
}

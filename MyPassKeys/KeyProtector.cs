using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MyPassKeys;

/// <summary>
/// Envelope-encrypts tenant JWT signing private keys before they are persisted, so a database
/// dump (or Redis dump of the tenant cache) alone is not enough to forge tokens. The
/// key-encryption key (KEK) lives only in app configuration (environment / secret store) —
/// never in the database. This protects against an attacker with DB access; it does NOT
/// protect against an attacker who compromises the app process itself.
/// </summary>
public interface IKeyProtector
{
    /// <summary>Encrypts a plaintext private JWK under the current KEK. <paramref name="kid"/>
    /// is bound as AAD so ciphertexts cannot be swapped between key entries undetected.</summary>
    JsonElement Protect(JsonElement privateKeyJwk, string kid);

    /// <summary>Returns the plaintext private JWK. Legacy plaintext values (pre-migration
    /// documents or stale cache entries) pass through unchanged; encrypted values are decrypted
    /// with the KEK identified in the blob. Throws when the KEK is unknown or the ciphertext
    /// fails its integrity check.</summary>
    JsonElement Unprotect(JsonElement stored, string kid);

    /// <summary>True when <paramref name="stored"/> is already encrypted under the CURRENT KEK.
    /// False for plaintext or previous-KEK ciphertexts — the startup migration re-encrypts those.</summary>
    bool IsProtectedWithCurrentKey(JsonElement stored);
}

/// <summary>
/// AES-256-GCM implementation. Encrypted blob shape (stored in <see cref="JwtKeyEntry.PrivateKey"/>):
/// <c>{"enc":"A256GCM","kek":"&lt;kek id&gt;","iv":"...","ct":"...","tag":"..."}</c>. The "enc"
/// property distinguishes it from a plaintext JWK (which has "kty" instead). "kek" is the first
/// 8 bytes of SHA-256 of the KEK, so decryption picks the right key during KEK rotation:
/// configure the new key as MyPassKeys:KeyEncryptionKey and the old one under
/// MyPassKeys:PreviousKeyEncryptionKeys — the startup migration re-encrypts everything under
/// the current KEK, after which the previous entry can be removed.
/// </summary>
public sealed class AesGcmKeyProtector : IKeyProtector
{
    private const string Algorithm = "A256GCM";
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;
    private const int KekSizeBytes = 32;

    private readonly byte[] _currentKek;
    private readonly string _currentKekId;
    private readonly Dictionary<string, byte[]> _kekById;

    public AesGcmKeyProtector(byte[] currentKek, IEnumerable<byte[]>? previousKeks = null)
    {
        if (currentKek.Length != KekSizeBytes)
            throw new ArgumentException($"Key-encryption key must be exactly {KekSizeBytes} bytes.", nameof(currentKek));

        _currentKek = currentKek;
        _currentKekId = ComputeKekId(currentKek);
        _kekById = new Dictionary<string, byte[]> { [_currentKekId] = currentKek };
        foreach (var kek in previousKeks ?? [])
        {
            if (kek.Length != KekSizeBytes)
                throw new ArgumentException($"Previous key-encryption keys must be exactly {KekSizeBytes} bytes.", nameof(previousKeks));
            _kekById.TryAdd(ComputeKekId(kek), kek);
        }
    }

    public static AesGcmKeyProtector FromConfiguration(IConfiguration configuration)
    {
        var (current, previous) = KekConfig.Load(configuration);
        return new AesGcmKeyProtector(current, previous);
    }

    public JsonElement Protect(JsonElement privateKeyJwk, string kid)
    {
        var plaintext = Encoding.UTF8.GetBytes(privateKeyJwk.GetRawText());
        try
        {
            var iv = RandomNumberGenerator.GetBytes(NonceSizeBytes);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSizeBytes];
            using (var gcm = new AesGcm(_currentKek, TagSizeBytes))
                gcm.Encrypt(iv, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(kid));

            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteString("enc", Algorithm);
                writer.WriteString("kek", _currentKekId);
                writer.WriteBase64String("iv", iv);
                writer.WriteBase64String("ct", ciphertext);
                writer.WriteBase64String("tag", tag);
                writer.WriteEndObject();
            }
            using var doc = JsonDocument.Parse(buffer.ToArray());
            return doc.RootElement.Clone();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public JsonElement Unprotect(JsonElement stored, string kid)
    {
        if (!IsEncrypted(stored))
            return stored; // legacy plaintext JWK — pre-migration document or stale cached tenant

        var kekId = stored.GetProperty("kek").GetString() ?? "";
        if (!_kekById.TryGetValue(kekId, out var kek))
            throw new InvalidOperationException(
                $"Signing key (kid '{kid}') is encrypted under an unknown key-encryption key '{kekId}'. " +
                "If the KEK was rotated, add the old key to MyPassKeys:PreviousKeyEncryptionKeys and restart.");

        var iv = stored.GetProperty("iv").GetBytesFromBase64();
        var ciphertext = stored.GetProperty("ct").GetBytesFromBase64();
        var tag = stored.GetProperty("tag").GetBytesFromBase64();
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using (var gcm = new AesGcm(kek, TagSizeBytes))
                gcm.Decrypt(iv, ciphertext, tag, plaintext, Encoding.UTF8.GetBytes(kid));

            using var doc = JsonDocument.Parse(plaintext);
            return doc.RootElement.Clone();
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException(
                $"Signing key (kid '{kid}') failed its integrity check — wrong key-encryption key or " +
                "tampered/moved ciphertext. Refusing to sign.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public bool IsProtectedWithCurrentKey(JsonElement stored) =>
        IsEncrypted(stored)
        && stored.TryGetProperty("kek", out var kekId)
        && kekId.GetString() == _currentKekId;

    /// <summary>A stored value is encrypted iff it carries the "enc" marker property; a plaintext JWK has "kty".</summary>
    public static bool IsEncrypted(JsonElement stored) =>
        stored.ValueKind == JsonValueKind.Object && stored.TryGetProperty("enc", out _);

    private static string ComputeKekId(byte[] kek) => KekConfig.ComputeKekId(kek);
}

/// <summary>
/// Loads the key-encryption-key ring from configuration. Shared by <see cref="AesGcmKeyProtector"/>
/// (signing-key encryption at rest) and <see cref="HmacDocumentIntegrity"/> (document integrity
/// seals — which derives its own HMAC keys from the same KEKs via HKDF, so no second secret
/// needs to be provisioned or rotated).
/// </summary>
public static class KekConfig
{
    public const int KekSizeBytes = 32;

    public static (byte[] Current, List<byte[]> Previous) Load(IConfiguration configuration)
    {
        var current = configuration["MyPassKeys:KeyEncryptionKey"];
        if (string.IsNullOrWhiteSpace(current))
            throw new InvalidOperationException(
                "MyPassKeys:KeyEncryptionKey must be configured — tenant JWT signing keys are encrypted at rest " +
                "with it, so a database dump alone cannot forge tokens. Generate one with 'openssl rand -base64 32' " +
                "and supply it via environment variable (MyPassKeys__KeyEncryptionKey) or a secret store. " +
                "Never store it in the database.");

        // Blank entries are ignored (not an error): production wires the previous KEK through a
        // compose env line that is only populated during a rotation (MyPassKeys__PreviousKeyEncryptionKeys__0),
        // so it is present-but-empty the rest of the time. Filter before decoding so an empty slot
        // doesn't fail startup.
        var previous = (configuration.GetSection("MyPassKeys:PreviousKeyEncryptionKeys").Get<string[]>() ?? [])
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .ToArray();
        return (
            DecodeKek(current, "MyPassKeys:KeyEncryptionKey"),
            previous.Select((k, i) => DecodeKek(k, $"MyPassKeys:PreviousKeyEncryptionKeys[{i}]")).ToList());
    }

    /// <summary>Stable public identifier for a KEK: first 8 bytes of its SHA-256, base64.</summary>
    public static string ComputeKekId(byte[] kek) =>
        Convert.ToBase64String(SHA256.HashData(kek).AsSpan(0, 8));

    private static byte[] DecodeKek(string base64, string configKey)
    {
        try
        {
            var kek = Convert.FromBase64String(base64.Trim());
            if (kek.Length != KekSizeBytes) throw new FormatException();
            return kek;
        }
        catch (FormatException)
        {
            throw new InvalidOperationException(
                $"{configKey} must be the base64 encoding of exactly {KekSizeBytes} random bytes " +
                "(generate with 'openssl rand -base64 32').");
        }
    }
}

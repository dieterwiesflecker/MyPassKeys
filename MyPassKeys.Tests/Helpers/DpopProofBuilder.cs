namespace MyPassKeys.Tests.Helpers;

using System.Security.Cryptography;
using System.Text.Json;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

public sealed class DpopProofBuilder : IDisposable
{
    private readonly ECDsa _ecKey;
    public string PublicJwkJson { get; }

    public DpopProofBuilder()
    {
        _ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(_ecKey));
        // Only public fields — no private 'd'
        PublicJwkJson = JsonSerializer.Serialize(new { kty = jwk.Kty, crv = jwk.Crv, x = jwk.X, y = jwk.Y });
    }

    /// Builds a valid DPoP proof signed with this instance's key.
    public string Build(
        string htm = "POST",
        string htu = "https://localhost/auth/make-assertion",
        DateTimeOffset? iat = null,
        string? jti = null,
        string typ = "dpop+jwt",
        string? ath = null,
        bool omitIat = false,
        bool omitJti = false)
    {
        var header = new JwtHeader(new SigningCredentials(new ECDsaSecurityKey(_ecKey), SecurityAlgorithms.EcdsaSha256));
        header["typ"] = typ;
        header["jwk"] = JsonSerializer.Deserialize<JsonElement>(PublicJwkJson);

        var payload = new JwtPayload { ["htm"] = htm, ["htu"] = htu };
        if (!omitIat) payload["iat"] = (long)(iat ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        if (!omitJti) payload["jti"] = jti ?? Guid.NewGuid().ToString();
        if (ath != null) payload["ath"] = ath;

        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
    }

    /// Signs with a DIFFERENT private key but embeds this builder's public key — signature validation will fail.
    public string BuildWithInvalidSignature(
        string htm = "POST",
        string htu = "https://localhost/auth/make-assertion")
    {
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var header = new JwtHeader(new SigningCredentials(new ECDsaSecurityKey(wrongKey), SecurityAlgorithms.EcdsaSha256));
        header["typ"] = "dpop+jwt";
        header["jwk"] = JsonSerializer.Deserialize<JsonElement>(PublicJwkJson); // correct public key, wrong signer

        var payload = new JwtPayload
        {
            ["htm"] = htm, ["htu"] = htu,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString()
        };
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
    }

    /// Builds a proof signed with HS256 (symmetric) — not in the allowed algorithm whitelist.
    public static string BuildWithWeakAlgorithm(
        string htm = "POST",
        string htu = "https://localhost/auth/make-assertion")
    {
        var symKey = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
        var header = new JwtHeader(new SigningCredentials(symKey, SecurityAlgorithms.HmacSha256));
        header["typ"] = "dpop+jwt";
        header["jwk"] = JsonSerializer.Deserialize<JsonElement>(
            """{"kty":"oct","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}""");

        var payload = new JwtPayload
        {
            ["htm"] = htm, ["htu"] = htu,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString()
        };
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
    }

    public void Dispose() => _ecKey.Dispose();
}

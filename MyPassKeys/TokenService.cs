using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;

namespace MyPassKeys;

public class TokenService(
    IConfiguration configuration,
    IConnectionMultiplexer redis,
    ILogger<TokenService> logger,
    ITenantService tenantService,
    IFido2DbService dbService,
    IKeyProtector keyProtector)
{
    private readonly string _defaultIssuer = configuration["Jwt:Issuer"] ?? "MyPassKeys";
    private readonly string _defaultAudience = configuration["Jwt:Audience"] ?? "MyPassKeys";

    public async Task<string> GenerateTokenAsync(Fido2AppUser user, string? dpopJsonWebKey = null)
    {
        logger.LogInformation("Generating Access Token for user {UserId}. DPoP Bound: {IsDpopBound}", user.Id, !string.IsNullOrEmpty(dpopJsonWebKey));

        var tenant = await tenantService.GetCurrentTenantAsync();
        if (tenant == null) throw new InvalidOperationException("Cannot generate token: current tenant could not be resolved.");
        var issuer = !string.IsNullOrEmpty(tenant.JwtIssuer) ? tenant.JwtIssuer : _defaultIssuer;
        var audience = !string.IsNullOrEmpty(tenant.JwtAudience) ? tenant.JwtAudience : _defaultAudience;
        var tokenLifetime = tenant.AccessTokenLifetimeInMinutes;

        var tokenHandler = new JwtSecurityTokenHandler();

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
            new("preferred_username", user.DisplayName),
            new("tenant_id", tenant.Id.ToString()),
        };

        // DPoP Binding: If a DPoP key is provided, bind the token to it via the 'cnf' claim
        if (!string.IsNullOrEmpty(dpopJsonWebKey))
        {
            var jkt = ComputeJwkThumbprint(dpopJsonWebKey);
            if (!string.IsNullOrEmpty(jkt))
            {
                // The cnf claim is a JSON object: { "jkt": "..." }
                // We serialize it to ensure it's treated as a JSON object claim
                var cnfPayload = JsonSerializer.Serialize(new { jkt });
                claims.Add(new Claim("cnf", cnfPayload, JsonClaimValueTypes.Json));
            }
        }

        // Effective roles = the user's direct roles plus roles inherited from group membership
        // (direct and via nested groups — AD-style). Each effective group is also emitted as a
        // 'groups' claim so resource servers can authorize on group membership directly.
        var allGroups = await dbService.GetGroupsAsync();
        var userGroups = TenantGroupModel.GroupsForUser(allGroups, user.Id);
        var effectiveRoles = user.Roles
            .Concat(userGroups.SelectMany(g => g.Roles))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        foreach (var role in effectiveRoles)
            claims.Add(new Claim("roles", role));
        foreach (var group in userGroups)
            claims.Add(new Claim("groups", group.Name));

        if (effectiveRoles.Count > 0)
        {
            var catalog = await dbService.GetRolesAsync();
            var scp = string.Join(" ", catalog
                .Where(r => effectiveRoles.Contains(r.Name))
                .SelectMany(r => r.Permissions)
                .Distinct(StringComparer.Ordinal));
            if (!string.IsNullOrEmpty(scp))
                claims.Add(new Claim("scp", scp));
        }

        var activeKey = tenant.JwtKeys.FirstOrDefault(k => k.IsActive)
            ?? throw new InvalidOperationException("Tenant has no active signing key.");
        var signingKey = ResolveSigningKey(keyProtector.Unprotect(activeKey.PrivateKey, activeKey.Kid));
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(tokenLifetime),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.EcdsaSha256)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    public async Task<string?> GetDpopKeyFromProof(string dpopProof, string httpMethod, string httpUrl)
    {
        var handler = new JwtSecurityTokenHandler();
        if (!handler.CanReadToken(dpopProof))
        {
            logger.LogWarning("GetDpopKeyFromProof: Cannot read DPoP proof as JWT.");
            return null;
        }

        try
        {
            var dpopJwt = handler.ReadJwtToken(dpopProof);

            // 1. Validate typ header — RFC 9449 §4.2: MUST be "dpop+jwt"
            if (!string.Equals(dpopJwt.Header.Typ, "dpop+jwt", StringComparison.OrdinalIgnoreCase))
            {
                logger.LogWarning("GetDpopKeyFromProof: 'typ' header is '{Typ}', expected 'dpop+jwt'.", dpopJwt.Header.Typ);
                return null;
            }

            // 2. Extract Public Key from DPoP Header (jwk)
            if (!dpopJwt.Header.TryGetValue("jwk", out var jwkObj))
            {
                logger.LogWarning("GetDpopKeyFromProof: 'jwk' header missing in DPoP proof.");
                return null;
            }
            var jwkJson = jwkObj.ToString();
            if (string.IsNullOrEmpty(jwkJson)) return null;

            // 3. Validate Signature using the embedded public key, whitelisting strong algorithms only
            var securityKey = new JsonWebKey(jwkJson);
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = securityKey,
                ValidateIssuerSigningKey = true,
                ValidAlgorithms = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]
            };

            handler.ValidateToken(dpopProof, validationParameters, out _);

            // 4. Validate Claims
            var payload = dpopJwt.Payload;

            // htm (HTTP Method)
            if (!payload.TryGetValue("htm", out var htm) || !string.Equals(htm.ToString(), httpMethod, StringComparison.OrdinalIgnoreCase))
            {
                logger.LogWarning("GetDpopKeyFromProof: HTTP Method mismatch. Expected: {Expected}, Found: {Found}", httpMethod, htm);
                return null;
            }

            // htu (HTTP URI)
            if (!payload.TryGetValue("htu", out var htu) || !string.Equals(htu.ToString(), httpUrl, StringComparison.OrdinalIgnoreCase))
            {
                logger.LogWarning("GetDpopKeyFromProof: HTTP URL mismatch. Expected: {Expected}, Found: {Found}", httpUrl, htu);
                return null;
            }

            // iat (Issued At) — must be recent to prevent pre-computed proof replay.
            // Check the raw claim before converting to avoid an overflow when IssuedAt is DateTime.MinValue.
            if (!payload.TryGetValue("iat", out _))
            {
                logger.LogWarning("GetDpopKeyFromProof: Missing 'iat' claim.");
                return null;
            }
            DateTimeOffset iat = payload.IssuedAt;

            var maxDpopAge = TimeSpan.FromMinutes(5);
            var dpopClockSkew = TimeSpan.FromMinutes(1);
            if (iat < DateTimeOffset.UtcNow.Subtract(maxDpopAge) || iat > DateTimeOffset.UtcNow.Add(dpopClockSkew))
            {
                logger.LogWarning("GetDpopKeyFromProof: 'iat' is outside the allowed time window.");
                return null;
            }

            // jti (JWT ID) — must be present and unused to prevent replay attacks
            if (string.IsNullOrEmpty(payload.Jti))
            {
                logger.LogWarning("GetDpopKeyFromProof: Missing 'jti' claim.");
                return null;
            }

            var db = redis.GetDatabase();
            var redisKey = DpopJtiReplayKey(payload.Jti);
            if (!await db.StringSetAsync(redisKey, "used", maxDpopAge, When.NotExists))
            {
                logger.LogWarning("GetDpopKeyFromProof: Replay detected — 'jti' '{Jti}' already used.", payload.Jti);
                return null;
            }

            return jwkJson;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "GetDpopKeyFromProof: Validation failed with exception.");
            return null;
        }
    }

    public async Task<ClaimsPrincipal?> ValidateTokenAsync(string token, string? dpopProof = null, string? httpMethod = null, string? httpUrl = null)
    {
        Tenant? tenant;
        try
        {
            tenant = await tenantService.GetCurrentTenantAsync();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "ValidateToken: tenant resolution failed.");
            return null;
        }
        return await ValidateTokenForTenantAsync(tenant, token, dpopProof, httpMethod, httpUrl);
    }

    /// <summary>
    /// Validates a token against an EXPLICIT tenant instead of the request's current tenant —
    /// same checks in full (signature via the tenant's keys, issuer/audience, lifetime, tenant-wide
    /// and per-user session cutoffs, and the complete DPoP proof validation incl. 'ath' binding and
    /// JTI replay). Used by the token-exchange endpoint, which must validate a subject token issued
    /// by a trusted tenant while the request itself is scoped to the target tenant.
    /// </summary>
    public async Task<ClaimsPrincipal?> ValidateTokenForTenantAsync(Tenant? tenant, string token, string? dpopProof = null, string? httpMethod = null, string? httpUrl = null)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        // JwtSecurityTokenHandler's DefaultInboundClaimTypeMap renames "scp" to the long-form
        // Microsoft URI (http://schemas.microsoft.com/identity/claims/scope), which makes the
        // downstream FindFirst("scp") permission checks (AuthorizePermissionAsync et al.) fail and
        // every /users and /roles call 403 despite a valid scope. Keep "scp" as-is. Same reason we
        // emit "tenant_id" instead of "tid" (see PortalEndpoints).
        tokenHandler.InboundClaimTypeMap.Remove("scp");

        try
        {
            var validIssuer = !string.IsNullOrEmpty(tenant?.JwtIssuer) ? tenant.JwtIssuer : _defaultIssuer;
            var validAudience = !string.IsNullOrEmpty(tenant?.JwtAudience) ? tenant.JwtAudience : _defaultAudience;

            var validationKeys = (tenant?.JwtKeys ?? [])
                .Select(k => (SecurityKey)ResolveValidationKey(k.PublicKey))
                .ToList();

            if (validationKeys.Count == 0)
                throw new InvalidOperationException("Tenant has no public keys configured.");

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = validationKeys,
                ValidAlgorithms = ["ES256"],
                ValidateIssuer = true,
                ValidIssuer = validIssuer,
                ValidateAudience = true,
                ValidAudience = validAudience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                RoleClaimType = "roles"
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

            // --- Session revocation checks ---
            // Reject access tokens issued before a tenant-wide or per-user "force re-login"
            // cutoff. Comparison is at whole-second (Unix time) granularity, matching the JWT
            // 'iat' claim — a token issued in the same second as the cutoff is allowed, so a
            // user re-authenticating immediately after a revocation is not locked out.
            if (validatedToken is JwtSecurityToken issuedJwt)
            {
                var issuedAtUnix = ToUnixSeconds(issuedJwt.IssuedAt);

                // Tenant-wide cutoff (set by POST /tenants/{id}/revoke-sessions).
                if (tenant != null && tenant.SessionsValidFrom > DateTime.MinValue
                    && issuedAtUnix < ToUnixSeconds(tenant.SessionsValidFrom))
                {
                    logger.LogWarning("ValidateToken: token rejected — issued before tenant-wide session cutoff.");
                    return null;
                }

                // Per-user cutoff (set by POST /users/{id}/revoke-sessions), stored in Redis.
                var revokedUserId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (tenant != null && !string.IsNullOrEmpty(revokedUserId))
                {
                    var revocationDb = redis.GetDatabase();
                    var cutoff = await revocationDb.StringGetAsync($"user-sessions-revoked:{tenant.Id}:{revokedUserId}");
                    if (cutoff.HasValue && cutoff.TryParse(out long cutoffUnix) && issuedAtUnix < cutoffUnix)
                    {
                        logger.LogWarning("ValidateToken: token rejected — issued before per-user session cutoff for user {UserId}.", revokedUserId);
                        return null;
                    }
                }
            }

            // DPoP Validation
            var cnfClaim = principal.FindFirst("cnf");
            if (cnfClaim != null)
            {
                // 1. If token has 'cnf', DPoP proof is mandatory
                if (string.IsNullOrEmpty(dpopProof) || string.IsNullOrEmpty(httpMethod) || string.IsNullOrEmpty(httpUrl))
                {
                    // Token is DPoP-bound but no proof provided
                    logger.LogWarning("ValidateToken: Token is DPoP-bound ('cnf' claim present), but DPoP proof or context is missing.");
                    return null;
                }

                // 2. Parse the DPoP proof (it's a JWT)
                var handler = new JwtSecurityTokenHandler();
                if (!handler.CanReadToken(dpopProof))
                {
                    logger.LogWarning("ValidateToken: Cannot read DPoP proof as JWT.");
                    return null;
                }
                var dpopJwt = handler.ReadJwtToken(dpopProof);

                // As per RFC 9449, the 'typ' header MUST be 'dpop+jwt'
                if (!string.Equals(dpopJwt.Header.Typ, "dpop+jwt", StringComparison.Ordinal))
                {
                    logger.LogWarning("ValidateToken: DPoP proof 'typ' header is '{Typ}', expected 'dpop+jwt'.", dpopJwt.Header.Typ);
                    return null;
                }

                // 3. Extract Public Key from DPoP Header (jwk)
                if (!dpopJwt.Header.TryGetValue("jwk", out var jwkObj))
                {
                    logger.LogWarning("ValidateToken: 'jwk' header missing in DPoP proof.");
                    return null;
                }
                var jwkJson = jwkObj.ToString();
                if (string.IsNullOrEmpty(jwkJson)) return null; // Should be caught above

                // 4. Validate DPoP Signature using the key inside the header
                var securityKey = new JsonWebKey(jwkJson);
                
                var dpopValidationParams = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false, // We check iat manually usually, but DPoP has no exp usually
                    IssuerSigningKey = securityKey,
                    ValidateIssuerSigningKey = true,
                    // Ensure we don't allow "None" algorithm or weak algs
                    ValidAlgorithms = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]
                };

                try 
                {
                    handler.ValidateToken(dpopProof, dpopValidationParams, out _);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "ValidateToken: DPoP proof signature validation failed.");
                    return null; // Signature failed
                }

                // 5. Validate DPoP Payload Claims
                var payload = dpopJwt.Payload;

                // 'iat' (Issued At) must be recent to prevent indefinite replay of DPoP proofs.
                if (!payload.TryGetValue("iat", out _))
                {
                    logger.LogWarning("ValidateToken: DPoP proof missing 'iat' claim.");
                    return null;
                }
                DateTimeOffset iat = payload.IssuedAt;

                var maxDpopAge = TimeSpan.FromMinutes(5); // Allow proofs up to 5 minutes old
                var dpopClockSkew = TimeSpan.FromMinutes(1); // Allow 1 minute clock drift for future
                if (iat < DateTimeOffset.UtcNow.Subtract(maxDpopAge) || iat > DateTimeOffset.UtcNow.Add(dpopClockSkew))
                {
                    logger.LogWarning("ValidateToken: DPoP proof 'iat' is outside the allowed time window.");
                    return null; // Proof is too old or from the future.
                }

                // htm (HTTP Method)
                if (!payload.TryGetValue("htm", out var htm) || !string.Equals(htm.ToString(), httpMethod, StringComparison.OrdinalIgnoreCase))
                {
                    logger.LogWarning("ValidateToken: DPoP 'htm' mismatch. Expected: {Expected}, Found: {Found}", httpMethod, htm);
                    return null;
                }

                // htu (HTTP URI) - Simple normalization might be needed in production
                if (!payload.TryGetValue("htu", out var htu) || !string.Equals(htu.ToString(), httpUrl, StringComparison.OrdinalIgnoreCase))
                {
                    logger.LogWarning("ValidateToken: DPoP 'htu' mismatch. Expected: {Expected}, Found: {Found}", httpUrl, htu);
                    return null;
                }

                // ath (Access Token Hash) - MUST match hash of the access token
                if (payload.TryGetValue("ath", out var ath))
                {
                    using var sha256 = SHA256.Create();
                    var tokenHashBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(token));
                    var tokenHash = Base64UrlEncoder.Encode(tokenHashBytes);
                    if (tokenHash != ath.ToString())
                    {
                        logger.LogWarning("ValidateToken: DPoP 'ath' mismatch. Proof not bound to this access token.");
                        return null;
                    }
                }
                else
                {
                    logger.LogWarning("ValidateToken: DPoP proof missing 'ath' claim.");
                    return null; // 'ath' is required when used with an access token
                }

                // 6. Validate Binding: 'cnf' in access token must match 'jkt' of DPoP key
                var jkt = ComputeJwkThumbprint(jwkJson);
                if (jkt == null)
                {
                    logger.LogWarning("ValidateToken: Failed to compute thumbprint for DPoP key.");
                    return null;
                }

                // Parse cnf JSON: { "jkt": "..." }
                try
                {
                    using var doc = JsonDocument.Parse(cnfClaim.Value);
                    if (!doc.RootElement.TryGetProperty("jkt", out var cnfJkt) || cnfJkt.GetString() != jkt)
                    {
                        logger.LogWarning("ValidateToken: DPoP binding mismatch. Token bound to different key.");
                        return null;
                    }

                }
                catch (JsonException ex)
                {
                    logger.LogError(ex, "ValidateToken: Failed to parse 'cnf' claim JSON.");
                    return null;
                }

                // 'jti' (JWT ID) is required and must be unique to prevent replay attacks.
                if (string.IsNullOrEmpty(payload.Jti))
                {
                    logger.LogWarning("ValidateToken: DPoP proof missing 'jti' claim.");
                    return null; // 'jti' is a required claim.
                }

                var db = redis.GetDatabase();
                var redisKey = DpopJtiReplayKey(payload.Jti);
                // Use StringSet with NX (NotExists) for an atomic check-and-set operation.
                if (!await db.StringSetAsync(redisKey, "used", maxDpopAge, When.NotExists))
                {
                    logger.LogWarning("ValidateToken: DPoP proof replay detected. JTI '{Jti}' already used.", payload.Jti);
                    return null; // Replay detected as JTI already exists in the cache.
                }
            }

            return principal;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "ValidateToken: Token validation failed.");
            return null;
        }
    }

    private static ECDsaSecurityKey ResolveSigningKey(JsonElement privateKeyJwk)
    {
        var jwk = new JsonWebKey(privateKeyJwk.GetRawText());
        var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = Base64UrlEncoder.DecodeBytes(jwk.D),
            Q = new ECPoint
            {
                X = Base64UrlEncoder.DecodeBytes(jwk.X),
                Y = Base64UrlEncoder.DecodeBytes(jwk.Y)
            }
        });
        return new ECDsaSecurityKey(ecdsa) { KeyId = jwk.KeyId };
    }

    private static ECDsaSecurityKey ResolveValidationKey(JsonElement publicKeyJwk)
    {
        var jwk = new JsonWebKey(publicKeyJwk.GetRawText());
        var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = Base64UrlEncoder.DecodeBytes(jwk.X),
                Y = Base64UrlEncoder.DecodeBytes(jwk.Y)
            }
        });
        return new ECDsaSecurityKey(ecdsa) { KeyId = jwk.KeyId };
    }

    /// <summary>Converts a DateTime to whole Unix seconds, matching the JWT 'iat' claim granularity.</summary>
    private static long ToUnixSeconds(DateTime dateTime) =>
        new DateTimeOffset(DateTime.SpecifyKind(dateTime, DateTimeKind.Utc)).ToUnixTimeSeconds();

    /// <summary>
    /// Reads the 'tenant_id' claim from a JWT WITHOUT validating it. Only for picking which
    /// tenant's keys to validate the token against — never trust it beyond that.
    /// </summary>
    public static Guid? ReadTenantIdClaim(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(token)) return null;
            var value = handler.ReadJwtToken(token).Claims.FirstOrDefault(c => c.Type == "tenant_id")?.Value;
            return Guid.TryParse(value, out var id) ? id : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Extracts the public JWK from a DPoP proof's header WITHOUT validating the proof. Only
    /// call after the proof has been validated (a validating pass consumes the proof's JTI, so
    /// re-validating just to get the key would trip replay detection).
    /// </summary>
    public static string? ReadDpopJwk(string dpopProof)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(dpopProof)) return null;
            return handler.ReadJwtToken(dpopProof).Header.TryGetValue("jwk", out var jwkObj)
                ? jwkObj.ToString()
                : null;
        }
        catch
        {
            return null;
        }
    }

    public static string? ComputeJwkThumbprint(string jwkJson)
    {
        try
        {
            var jwk = new JsonWebKey(jwkJson);
            // ComputeThumbprint returns the SHA256 hash of the canonical JWK
            var thumbprintBytes = jwk.ComputeJwkThumbprint();
            return Base64UrlEncoder.Encode(thumbprintBytes);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Builds the Redis replay-cache key for a DPoP proof's <c>jti</c>. The <c>jti</c> is
    /// attacker-controlled and unbounded in length; hashing it to a fixed 32-byte SHA-256 digest
    /// bounds the key size so a client cannot exhaust Redis memory by sending very large jti
    /// strings. The hash is one-way and per-proof unique, so replay detection is unaffected.
    /// </summary>
    public static string DpopJtiReplayKey(string jti)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(jti));
        return $"dpop-jti:{Convert.ToBase64String(digest)}";
    }

    /// <summary>
    /// Decodes the token to inspect its claims and header for debugging purposes.
    /// </summary>
    public Dictionary<string, object> InspectToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        if (string.IsNullOrEmpty(token) || !handler.CanReadToken(token))
        {
            return new Dictionary<string, object> { { "Error", "Invalid or unreadable JWT token." } };
        }

        var jwt = handler.ReadJwtToken(token);

        return new Dictionary<string, object>
        {
            { "Header", jwt.Header },
            { "Payload", jwt.Payload },
            { "ValidTo", jwt.ValidTo }
        };
    }
}
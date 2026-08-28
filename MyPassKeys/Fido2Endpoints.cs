using System.Security.Claims;
using System.Text;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Mvc;
using StackExchange.Redis;

namespace MyPassKeys;

public static class Fido2Endpoints
{
    public static void MapFido2Endpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("auth");

        // Generates the options required to create a new FIDO2 credential for the authenticated user.
        group.MapPost("make-credential-options", MakeCredentialOptions)
            .RequireRateLimiting("auth");
        //.RequireAuthorization();

        // Verifies the authenticator's attestation response and registers the new FIDO2 credential.
        group.MapPost("make-credential", MakeCredential)
            .RequireRateLimiting("auth");
        //.RequireAuthorization();

        // Generates the options required to assert (authenticate) with an existing FIDO2 credential.
        group.MapPost("assertion-options", AssertionOptions)
            .RequireRateLimiting("auth");

        // Verifies the authenticator's assertion response and issues a JWT token if successful.
        group.MapPost("make-assertion", MakeAssertion)
            .RequireRateLimiting("auth");

        // Exchanges a valid Refresh Token for a new Access Token (and rotates the Refresh Token).
        group.MapPost("refresh", RefreshToken)
            .RequireRateLimiting("refresh");

        // Silent app switch: exchanges a valid DPoP-bound access token issued by a TRUSTED tenant
        // for this tenant's tokens (same trust links + JIT provisioning as make-assertion, minus
        // the WebAuthn ceremony). Anonymous by design — the standard auth handler validates
        // against the CURRENT tenant's keys, but the subject token is signed by the home tenant,
        // so validation is done manually inside the handler.
        group.MapPost("exchange", ExchangeToken)
            .RequireRateLimiting("refresh");
    }

    /// <summary>
    /// Applies the tenant's registration-policy roles (Tenant.DefaultRoles / DomainRoles) to
    /// <paramref name="roles"/>, keeping only names present in the live role catalog so a stale
    /// policy entry can't grant a nonexistent role. Shared by self-registration and by JIT
    /// provisioning on a trusted cross-tenant login.
    /// </summary>
    private static async Task<List<string>> WithPolicyRolesAsync(
        Tenant tenant, string username, List<string> roles, IFido2DbService fido2DbService)
    {
        var policyRoles = RegistrationPolicy.RolesForRegistration(tenant, username.NormalizeUsername());
        if (policyRoles.Length == 0) return roles;
        var knownRoles = (await fido2DbService.GetRolesAsync()).Select(r => r.Name).ToHashSet();
        foreach (var role in policyRoles)
            if (knownRoles.Contains(role) && !roles.Contains(role))
                roles.Add(role);
        return roles;
    }

    /// <summary>
    /// Collects the credentials this username holds in every tenant the current tenant trusts
    /// (<see cref="Tenant.TrustedCredentialTenantIds"/>). Those same-domain passkeys are valid
    /// for login here, so assertion-options offers them and make-credential-options excludes
    /// them from duplicate registration.
    /// </summary>
    private static async Task<List<Fido2StoredCredential>> GetTrustedCredentialsByUsernameAsync(
        Tenant tenant, string username, IFido2DbService fido2DbService)
    {
        var result = new List<Fido2StoredCredential>();
        foreach (var trustedTenantId in tenant.TrustedCredentialTenantIds)
        {
            var trustedUser = await fido2DbService.GetUserByUsernameForTenantAsync(trustedTenantId, username);
            if (trustedUser == null) continue;
            result.AddRange(await fido2DbService.GetCredentialsByUserIdForTenantAsync(trustedTenantId, trustedUser.Id));
        }
        return result;
    }

    private static async Task<IResult> MakeCredentialOptions(
        [FromQuery] string? username,
        ClaimsPrincipal? userPrincipal,
        Fido2Service fido2Service,
        IFido2DbService fido2DbService,
        IConnectionMultiplexer redis,
        ITenantService tenantService,
        ILogger<Fido2EndpointsLog> logger)
    {
        try
        {
            // 1. Get current user info from ClaimsPrincipal (populated by Entra ID or existing Token)
            //var username = userPrincipal.FindFirst("preferred_username")?.Value ?? userPrincipal.Identity?.Name;
            username ??= userPrincipal?.FindFirst("preferred_username")?.Value ?? userPrincipal?.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();

            // 2. Resolve tenant + enforce per-tenant registration policy.
            var tenant = await tenantService.GetCurrentTenantAsync();
            if (tenant == null) return Results.BadRequest(new ErrorResponse("Unknown tenant"));

            var user = await fido2DbService.GetUserByUsernameAsync(username);
            var db = redis.GetDatabase();
            var verifiedKey = $"EmailVerified:{tenant.Id}:{username.NormalizeUsername()}";

            List<Fido2StoredCredential> existingCreds;
            if (user == null)
            {
                // Self-registration path. InviteOnly tenants do not accept it — the user must be
                // pre-created by an admin via POST /users.
                if (tenant.RegistrationMode == RegistrationModes.InviteOnly)
                    return Results.BadRequest(new ErrorResponse("Registration is by invitation only for this tenant."));

                // Open / DomainAllowlist: require a verified email before creating the user.
                var isVerified = await db.KeyExistsAsync(verifiedKey);
                if (!isVerified)
                    return Results.BadRequest(new ErrorResponse("Email not verified. Please verify your email first."));

                // Roles a self-registrant receives are driven by the tenant's registration policy:
                // Tenant.DefaultRoles in Open mode, or the per-domain Tenant.DomainRoles for the
                // matching allowlist entry in DomainAllowlist mode (see WithPolicyRolesAsync).
                // When the policy grants nothing, the historical behavior holds: portal/management
                // signups and unconfigured tenants get no default roles. Any roles carried on the
                // principal (e.g. an upstream IdP) are preserved and unioned in.
                var grantedRoles = await WithPolicyRolesAsync(tenant, username,
                    userPrincipal?.FindAll("roles").Select(c => c.Value).ToList() ?? [], fido2DbService);

                user = new Fido2AppUser
                {
                    Username = username,
                    DisplayName = userPrincipal?.Identity?.Name ?? username,
                    Roles = grantedRoles
                };
                await fido2DbService.UpsertUserAsync(user);
                await db.KeyDeleteAsync(verifiedKey);
                existingCreds = [];
            }
            else
            {
                existingCreds = await fido2DbService.GetCredentialsByUserIdAsync(user.Id);

                // For all modes: gate passkey addition behind email verification unless the caller
                // is already authenticated as this user (e.g. adding a second passkey from a live
                // session). This covers first registration, recovery, and invite-only alike.
                var isAuthenticated = userPrincipal?.Identity?.IsAuthenticated == true
                    && userPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value == user.Id.ToString();
                if (!isAuthenticated)
                {
                    var isVerified = await db.KeyExistsAsync(verifiedKey);
                    if (!isVerified)
                        return Results.BadRequest(new ErrorResponse("Email not verified. Please verify your email first."));
                    await db.KeyDeleteAsync(verifiedKey);
                }
            }

            // 3. Build exclusion list from existing credentials — including same-domain passkeys
            // held in trusted tenants, so the authenticator refuses to mint a duplicate passkey
            // for a user who can already log in here with a trusted credential (make-assertion
            // accepts those directly).
            foreach (var trustedCred in await GetTrustedCredentialsByUsernameAsync(tenant, username, fido2DbService))
                if (existingCreds.All(c => c.Id != trustedCred.Id))
                    existingCreds.Add(trustedCred);
            var excludeCredentials =
                existingCreds.Select(c => new PublicKeyCredentialDescriptor(c.CredentialId)).ToList();

            // 4. Create options
            var userEntity = new Fido2User
            {
                DisplayName = user.DisplayName,
                Name = user.Username,
                Id = Encoding.UTF8.GetBytes(user.Id.ToString()),
            };

            var options = await fido2Service.CreateOptionsAsync(userEntity, excludeCredentials);

            // 5. Store options/challenge temporarily
            await fido2DbService.StoreChallengeAsync(user.Username, options.ToJson());

            return Results.Ok(options);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error in MakeCredentialOptions");
            return Results.BadRequest(new ErrorResponse("Failed to create credential options"));
        }
    }

    private static async Task<IResult> MakeCredential(
        [FromBody] AuthenticatorAttestationRawResponse response,
        [FromQuery] string? username,
        ClaimsPrincipal userPrincipal,
        Fido2Service fido2Service,
        IFido2DbService fido2DbService,
        TokenService tokenService,
        ITenantService tenantService,
        ILogger<Fido2EndpointsLog> logger,
        HttpContext httpContext)
    {
        try
        {
            username ??= userPrincipal.FindFirst("preferred_username")?.Value ??
                         userPrincipal.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();

            // 1. Get the challenge we stored
            var optionsJson = await fido2DbService.GetChallengeAsync(username);
            if (string.IsNullOrEmpty(optionsJson)) return Results.BadRequest("Challenge expired or not found");

            var options = CredentialCreateOptions.FromJson(optionsJson);

            // 3. Verify
            var success = await fido2Service.CompleteRegistrationAsync(response, options, CheckCredentialIsUniqueCallback);

            // 4. Save Credential
            var user = await fido2DbService.GetUserByUsernameAsync(username);
            if (user == null)
            {
                return Results.BadRequest("User not found");
            }

            var newCred = new Fido2StoredCredential
            {
                // Use Base64Url of the CredentialId as the DB Key to match GetCredentialByIdAsync logic
                Id = success.Id.ToBase64Url(),
                //id = Guid.CreateVersion7().ToString();
                Transports = [], // Todo: fill in values

                CredentialId = success.Id,
                PublicKey = success.PublicKey,
                UserId = user.Id,
                RegDate = DateTime.UtcNow,
                AaGuid = success.AaGuid,
                SignatureCounter = success.SignCount,
                CredType = success.Type.ToString(),
                IsBackedUp = success.IsBackedUp,
                IsBackupEligible = success.IsBackupEligible,
                AttestationObject = success.AttestationObject,

                ClientDataJson = success.AttestationClientDataJson,
            };

            await fido2DbService.UpsertCredentialAsync(newCred);

            // 5. Generate JWT for immediate login
            string? dpopKey = null;
            if (httpContext.Request.Headers.TryGetValue("DPoP", out var dpopProof))
            {
                var method = httpContext.Request.Method;
                var url =
                    $"{httpContext.Request.Scheme}://{httpContext.Request.Host}{httpContext.Request.PathBase}{httpContext.Request.Path}";
                dpopKey = await tokenService.GetDpopKeyFromProof(dpopProof.ToString(), method, url);
                if (dpopKey == null)
                {
                    logger.LogWarning("Invalid DpopKey proof during login");
                    return Results.BadRequest(new ErrorResponse("Dpop key not found"));
                }
            }

            var token = await tokenService.GenerateTokenAsync(user, dpopKey);
            var refreshToken = await GenerateAndStoreRefreshToken(user, dpopKey, tokenService, fido2DbService, tenantService);

            return Results.Ok(new LoginResponse(token, refreshToken, user));

            // Create callback to check if credential ID is unique
            async Task<bool> CheckCredentialIsUniqueCallback(IsCredentialIdUniqueToUserParams args, CancellationToken cancellationToken)
            {
                var cred = await fido2DbService.GetCredentialByIdAsync(args.CredentialId);
                return cred == null;
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error in MakeCredential");
            return Results.BadRequest(new ErrorResponse("Registration failed"));
        }
    }

    private static async Task<IResult> AssertionOptions(
        [FromBody] AssertionOptionsRequest request,
        Fido2Service fido2Service,
        IFido2DbService fido2DbService,
        ITenantService tenantService,
        ILogger<Fido2EndpointsLog> logger)
    {
        try
        {
            var username = request?.Username;

            if (string.IsNullOrEmpty(username))
                return Results.BadRequest(new ErrorResponse("Username is required"));

            var tenant = await tenantService.GetCurrentTenantAsync();
            if (tenant == null) return Results.BadRequest(new ErrorResponse("Unknown tenant"));

            // 1. Get user existing credentials.
            // Do NOT return 404 for unknown users — that would allow username enumeration.
            // An empty allow-list is returned for unknown users, which is indistinguishable
            // from a valid response to the client. make-assertion will reject the attempt.
            var user = await fido2DbService.GetUserByUsernameAsync(username);
            var allowCredentials = user != null
                ? (await fido2DbService.GetCredentialsByUserIdAsync(user.Id))
                    .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId)).ToList()
                : [];

            // Same-domain passkeys registered in trusted tenants are valid for login here
            // (make-assertion resolves them cross-tenant), so offer them in the allow-list too.
            // Unknown-everywhere usernames still get the same empty list — no enumeration signal.
            foreach (var trustedCred in await GetTrustedCredentialsByUsernameAsync(tenant, username, fido2DbService))
                if (allowCredentials.All(d => !d.Id.SequenceEqual(trustedCred.CredentialId)))
                    allowCredentials.Add(new PublicKeyCredentialDescriptor(trustedCred.CredentialId));

            // 2. Create options
            var options = await fido2Service.BeginAuthenticationAsync(allowCredentials);

            // 3. Store challenge (stored even for unknown users; make-assertion will fail at credential lookup)
            await fido2DbService.StoreChallengeAsync(username, options.ToJson());

            return Results.Ok(options);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error in AssertionOptions");
            return Results.BadRequest(new ErrorResponse("Failed to create assertion options"));
        }
    }

    /// <summary>
    /// Verifies the assertion response from the authenticator and generates a JWT token upon success.
    /// </summary>
    private static async Task<IResult> MakeAssertion(
        [FromBody] AuthenticatorAssertionRawResponse response,
        [FromQuery] string username,
        Fido2Service fido2Service,
        IFido2DbService fido2DbService,
        TokenService tokenService,
        ITenantService tenantService,
        ILogger<Fido2EndpointsLog> logger,
        HttpContext httpContext)
    {
        try
        {
            if (string.IsNullOrEmpty(username)) return Results.BadRequest(new ErrorResponse("Username query parameter is required"));

            // 1. Get Challenge
            var optionsJson = await fido2DbService.GetChallengeAsync(username);
            if (string.IsNullOrEmpty(optionsJson)) return Results.BadRequest(new ErrorResponse("Challenge expired"));
            var options = Fido2NetLib.AssertionOptions.FromJson(optionsJson);

            var tenant = await tenantService.GetCurrentTenantAsync();
            if (tenant == null) return Results.Unauthorized();

            // 2. Get Credential from DB — locally first, then across the tenants this tenant
            // trusts (same-domain passkeys registered in a linked tenant are accepted here;
            // see Tenant.TrustedCredentialTenantIds).
            var cred = await fido2DbService.GetCredentialByIdAsync(response.Id)
                       ?? await fido2DbService.GetCredentialByIdForTenantsAsync(
                           response.Id, tenant.TrustedCredentialTenantIds);
            if (cred == null) return Results.Unauthorized();

            // 3. Verify — ensure the userHandle returned by the authenticator matches the credential's owner
            var result = await fido2Service.CompleteAuthenticationAsync(response, options, cred.PublicKey,
                cred.SignatureCounter, (args, ct) =>
                {
                    var userHandleStr = Encoding.UTF8.GetString(args.UserHandle);
                    return Task.FromResult(Guid.TryParse(userHandleStr, out var userHandleId) && cred.UserId == userHandleId);
                });

            // 4. Update Counter — always against the credential's HOME tenant. A trusted tenant's
            // credential stays single-homed there (the current-tenant upsert would silently re-home
            // it, splitting SignatureCounter tracking and clone detection).
            cred.SignatureCounter = result.SignCount;
            await fido2DbService.UpsertCredentialForTenantAsync(cred.TenantId, cred);

            // 5. Generate JWT for the VERIFIED credential owner.
            // The assertion was verified against cred.PublicKey and the authenticator's userHandle
            // was checked to equal cred.UserId, so cred.UserId is the authenticated identity. The
            // `username` query parameter is caller-controlled and MUST NOT decide the token subject:
            // otherwise anyone holding a single valid credential could mint a token for another user
            // simply by passing that user's username. Resolve the subject from the credential and
            // reject if the claimed username doesn't match its owner.
            var owner = await fido2DbService.GetUserByIdForTenantAsync(cred.TenantId, cred.UserId);
            if (owner == null)
            {
                logger.LogWarning("MakeAssertion: credential {CredId} references a missing user {UserId}.", cred.Id, cred.UserId);
                return Results.Unauthorized();
            }
            if (!string.Equals(owner.Username, username.NormalizeUsername(), StringComparison.Ordinal))
            {
                logger.LogWarning("MakeAssertion: supplied username does not match the credential owner for credential {CredId}.", cred.Id);
                return Results.Unauthorized();
            }

            // Resolve the LOCAL token subject. For a credential homed in this tenant that is the
            // owner itself; for a trusted tenant's credential it is the local membership with the
            // same (already vetted) username — created just-in-time when this tenant's registration
            // policy allows. Rights stay strictly per-tenant: a JIT user starts with only this
            // tenant's policy-default roles; nothing is copied from the credential's home tenant.
            var user = cred.TenantId == tenant.Id
                ? owner
                : await fido2DbService.GetUserByUsernameAsync(owner.Username);
            if (user == null)
            {
                if (!RegistrationPolicy.CanJitProvision(tenant, owner.Username))
                {
                    logger.LogWarning(
                        "MakeAssertion: trusted-tenant login rejected — registration policy '{Mode}' forbids JIT provisioning.",
                        tenant.RegistrationMode);
                    return Results.Unauthorized();
                }
                user = new Fido2AppUser
                {
                    Username = owner.Username,
                    DisplayName = owner.DisplayName,
                    Roles = await WithPolicyRolesAsync(tenant, owner.Username, [], fido2DbService)
                };
                await fido2DbService.UpsertUserAsync(user);
                logger.LogInformation(
                    "MakeAssertion: JIT-provisioned user {UserId} from trusted tenant {HomeTenantId}.",
                    user.Id, cred.TenantId);
            }

            // --- DPoP Logic Start ---
            string? dpopJsonWebKey = null;

            // Check if the client sent a DPoP header
            if (httpContext.Request.Headers.TryGetValue("DPoP", out var dpopProof) && !string.IsNullOrEmpty(dpopProof))
            {
                var method = httpContext.Request.Method;
                var url = $"{httpContext.Request.Scheme}://{httpContext.Request.Host}{httpContext.Request.PathBase}{httpContext.Request.Path}";

                // FIX: Use TokenService to VALIDATE the proof signature before accepting the key
                dpopJsonWebKey = await tokenService.GetDpopKeyFromProof(dpopProof.ToString(), method, url);
                
                if (dpopJsonWebKey == null)
                {
                    logger.LogWarning("MakeAssertion: Invalid DPoP proof provided.");
                    return Results.BadRequest(new ErrorResponse("Invalid DPoP proof."));
                }
            }
            // --- DPoP Logic End ---

            // Pass the extracted key to your generator to bind the token
            var token = await tokenService.GenerateTokenAsync(user, dpopJsonWebKey);
            
            var refreshToken = await GenerateAndStoreRefreshToken(user, dpopJsonWebKey, tokenService, fido2DbService, tenantService);

            return Results.Ok(new LoginResponse(token, refreshToken, user));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error in MakeAssertion");
            return Results.BadRequest(new ErrorResponse("Authentication failed"));
        }
    }

    /// <summary>
    /// Cross-tenant token exchange for silent app switching between tenants linked by
    /// <see cref="Tenant.TrustedCredentialTenantIds"/>. The caller presents an access token
    /// issued by a tenant the CURRENT tenant trusts, plus a fresh DPoP proof for THIS request
    /// (htm/htu of the exchange call, 'ath' of the subject token) proving possession of the key
    /// the subject token is bound to. On success the same JIT rules as make-assertion apply and
    /// tokens are minted for the current tenant, bound to the same DPoP key. Every rejection is
    /// the same generic 401.
    /// </summary>
    private static async Task<IResult> ExchangeToken(
        [FromBody] ExchangeTokenRequest request,
        [FromHeader(Name = "DPoP")] string? dpopProof,
        IFido2DbService fido2DbService,
        TokenService tokenService,
        ITenantService tenantService,
        ILogger<Fido2EndpointsLog> logger,
        HttpContext httpContext)
    {
        try
        {
            var tenant = await tenantService.GetCurrentTenantAsync();
            if (tenant == null || tenant.TrustedCredentialTenantIds.Length == 0)
                return Results.Unauthorized();
            if (string.IsNullOrEmpty(request.SubjectToken) || string.IsNullOrEmpty(dpopProof))
                return Results.Unauthorized();

            // The unvalidated tenant_id claim only selects WHICH trusted tenant's keys must then
            // actually validate the token — a lie here just fails signature validation below.
            var homeTenantId = TokenService.ReadTenantIdClaim(request.SubjectToken);
            if (homeTenantId == null || !tenant.TrustedCredentialTenantIds.Contains(homeTenantId.Value))
                return Results.Unauthorized();
            var homeTenant = await fido2DbService.GetTenantByIdAsync(homeTenantId.Value);
            if (homeTenant == null) return Results.Unauthorized();

            // Full validation against the HOME tenant: signature, issuer/audience, lifetime,
            // session cutoffs, and the DPoP proof (htm/htu of this request, 'ath', jkt binding,
            // JTI replay). A revoked home session therefore cannot be exchanged.
            var method = httpContext.Request.Method;
            var url = $"{httpContext.Request.Scheme}://{httpContext.Request.Host}{httpContext.Request.PathBase}{httpContext.Request.Path}";
            var principal = await tokenService.ValidateTokenForTenantAsync(
                homeTenant, request.SubjectToken, dpopProof, method, url);
            if (principal == null) return Results.Unauthorized();

            // Mirror the auth handler: a subject token without DPoP binding is refused outright.
            if (principal.FindFirst("cnf") == null)
            {
                logger.LogWarning("ExchangeToken: subject token is not DPoP-bound — refused.");
                return Results.Unauthorized();
            }

            // Resolve the authenticated home user from the VALIDATED token subject — never from
            // caller-supplied values.
            if (!Guid.TryParse(principal.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var homeUserId))
                return Results.Unauthorized();
            var owner = await fido2DbService.GetUserByIdForTenantAsync(homeTenant.Id, homeUserId);
            if (owner == null) return Results.Unauthorized();

            // Local subject + JIT provisioning — identical rules to make-assertion.
            var user = await fido2DbService.GetUserByUsernameAsync(owner.Username);
            if (user == null)
            {
                if (!RegistrationPolicy.CanJitProvision(tenant, owner.Username))
                {
                    logger.LogWarning(
                        "ExchangeToken: exchange rejected — registration policy '{Mode}' forbids JIT provisioning.",
                        tenant.RegistrationMode);
                    return Results.Unauthorized();
                }
                user = new Fido2AppUser
                {
                    Username = owner.Username,
                    DisplayName = owner.DisplayName,
                    Roles = await WithPolicyRolesAsync(tenant, owner.Username, [], fido2DbService)
                };
                await fido2DbService.UpsertUserAsync(user);
                logger.LogInformation(
                    "ExchangeToken: JIT-provisioned user {UserId} from trusted tenant {HomeTenantId}.",
                    user.Id, homeTenant.Id);
            }

            // Bind the new tokens to the SAME key the subject token proved possession of.
            var dpopJsonWebKey = TokenService.ReadDpopJwk(dpopProof);
            var token = await tokenService.GenerateTokenAsync(user, dpopJsonWebKey);
            var refreshToken = await GenerateAndStoreRefreshToken(user, dpopJsonWebKey, tokenService, fido2DbService, tenantService);

            logger.LogInformation(
                "ExchangeToken: issued tokens for user {UserId} (from trusted tenant {HomeTenantId}).",
                user.Id, homeTenant.Id);
            return Results.Ok(new LoginResponse(token, refreshToken, user));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error in ExchangeToken");
            return Results.Unauthorized();
        }
    }

    private static async Task<IResult> RefreshToken(
        [FromBody] RefreshTokenRequest request,
        [FromHeader(Name = "DPoP")] string? dpopProof,
        IFido2DbService fido2DbService,
        TokenService tokenService,
        ITenantService tenantService,
        ILogger<Fido2EndpointsLog> logger,
        HttpContext httpContext)
    {
        try
        {
            logger.LogInformation("RefreshToken endpoint called.");

            // 1. Validate DPoP if present (Required if the original session was DPoP bound)
            string? dpopJkt = null;
            string? dpopJsonWebKey = null;

            if (!string.IsNullOrEmpty(dpopProof))
            {
                logger.LogDebug("Processing DPoP proof.");
                var method = httpContext.Request.Method;
                var url = $"{httpContext.Request.Scheme}://{httpContext.Request.Host}{httpContext.Request.PathBase}{httpContext.Request.Path}";
                
                // Validate proof and extract key
                dpopJsonWebKey = await tokenService.GetDpopKeyFromProof(dpopProof, method, url);
                if (dpopJsonWebKey == null)
                {
                    logger.LogWarning("Invalid DPoP proof.");
                    return Results.Unauthorized(); // Invalid DPoP proof
                }

                dpopJkt = TokenService.ComputeJwkThumbprint(dpopJsonWebKey);
            }

            // 2. Get Refresh Token
            var hashedRequestToken = HashToken(request.RefreshToken);
            var storedToken = await fido2DbService.GetRefreshTokenAsync(hashedRequestToken);
            
            // Check existence and expiry
            if (storedToken == null || storedToken.Expiry < DateTime.UtcNow)
            {
                logger.LogWarning("Refresh token not found or expired.");
                return Results.Unauthorized();
            }

            // Check for revocation (potential replay attack).
            if (storedToken.IsRevoked)
            {
                // Reuse of an already-rotated token is either (a) a benign concurrent multi-tab
                // refresh racing the rotation, or (b) a stolen token being replayed. We tell them
                // apart by age: within a short grace window of rotation it's almost certainly a
                // race, so we only reject this one request. Outside the window it's treated as a
                // compromise and we revoke the user's entire refresh-token family — the legitimate
                // client will simply re-authenticate.
                if (IsReplayOutsideGraceWindow(storedToken.RevokedAt, DateTime.UtcNow))
                {
                    logger.LogWarning(
                        "Refresh token replay outside grace window for user {UserId} — revoking all sessions.",
                        storedToken.UserId);
                    await fido2DbService.RevokeUserRefreshTokensAsync(storedToken.UserId);
                }
                else
                {
                    logger.LogInformation(
                        "Revoked refresh token reused within grace window for user {UserId} (likely concurrent tab).",
                        storedToken.UserId);
                }

                // Return the same generic error in both cases to not leak which branch was taken.
                return Results.Unauthorized();
            }

            // 3. Verify DPoP Binding
            // If the refresh token was issued to a specific key, the refresher must prove possession of that key.
            if (!string.IsNullOrEmpty(storedToken.DpopJkt))
            {
                if (dpopJkt != storedToken.DpopJkt)
                {
                    logger.LogWarning("DPoP binding mismatch. Token JKT: {TokenJkt}, Proof JKT: {ProofJkt}", storedToken.DpopJkt, dpopJkt);
                    return Results.Unauthorized();
                }
            }

            // 4. Rotate Token (Revoke old, create new)
            /*storedToken.IsRevoked = true;
            await fido2DbService.UpsertRefreshTokenAsync(storedToken);*/

            var user = await fido2DbService.GetUserByIdAsync(storedToken.UserId);
            if (user == null)
            {
                logger.LogError("User not found for valid refresh token. UserId: {UserId}", storedToken.UserId);
                return Results.Unauthorized();
            }

            // 4. Generate new tokens FIRST
            var newAccessToken = await tokenService.GenerateTokenAsync(user, dpopJsonWebKey);
            var newRefreshToken = await GenerateAndStoreRefreshToken(user, dpopJsonWebKey, tokenService, fido2DbService, tenantService);

            // 5. Rotate Token (Revoke old) LAST.
            // Doing this after new tokens are generated ensures the user isn't left without a session if generation fails.
            storedToken.IsRevoked = true;
            storedToken.RevokedAt = DateTime.UtcNow;
            await fido2DbService.UpsertRefreshTokenAsync(storedToken);


            logger.LogInformation("Token refreshed successfully for user {Username}", user.Username);
            return Results.Ok(new LoginResponse(newAccessToken, newRefreshToken, user));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error in RefreshToken");
            return Results.BadRequest(new ErrorResponse("Token refresh failed"));
        }
    }

    private static async Task<string> GenerateAndStoreRefreshToken(Fido2AppUser user, string? dpopJsonWebKey, TokenService tokenService, IFido2DbService dbService, ITenantService tenantService)
    {
        var tenant = await tenantService.GetCurrentTenantAsync();
        var refreshTokenLifetime = tenant?.RefreshTokenLifetimeInHours ?? 720;

        var refreshToken = tokenService.GenerateRefreshToken();
        var entity = new Fido2RefreshToken
        {
            Id = Guid.CreateVersion7(),
            Token = HashToken(refreshToken),
            UserId = user.Id,
            Expiry = DateTime.UtcNow.AddHours(refreshTokenLifetime),
            DpopJkt = !string.IsNullOrEmpty(dpopJsonWebKey) ? TokenService.ComputeJwkThumbprint(dpopJsonWebKey) : null
        };
        await dbService.UpsertRefreshTokenAsync(entity);
        return refreshToken;
    }

    /// <summary>
    /// Grace window for tolerating a concurrent-tab replay of a just-rotated refresh token before
    /// treating reuse as a compromise.
    /// </summary>
    internal static readonly TimeSpan RefreshReplayGraceWindow = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Decides whether reuse of an already-revoked refresh token should trigger family-wide
    /// revocation. True (a genuine replay) when the token was revoked longer ago than the grace
    /// window. A null <paramref name="revokedAt"/> (legacy tokens rotated before the field existed)
    /// is treated as revoked "now", i.e. within the window, so we fail safe toward the benign case.
    /// </summary>
    internal static bool IsReplayOutsideGraceWindow(DateTime? revokedAt, DateTime now) =>
        now - (revokedAt ?? now) > RefreshReplayGraceWindow;

    private static string HashToken(string token)
    {
        var hashBytes = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToBase64String(hashBytes);
    }

    // Dummy class for Logger generic
    public class Fido2EndpointsLog
    {
    }

    /// <summary>
    /// Request to initiate the authentication (login) process.
    /// </summary>
    /// <param name="Username">The username of the user attempting to log in.</param>
    public record AssertionOptionsRequest(string Username);

    /// <summary>
    /// The successful login response containing tokens and user details.
    /// </summary>
    /// <param name="Token">The short-lived JWT Access Token.</param>
    /// <param name="RefreshToken">The long-lived Refresh Token used to renew the Access Token.</param>
    /// <param name="User">The authenticated user profile.</param>
    public record LoginResponse(string Token, string RefreshToken, Fido2AppUser User);

    /// <summary>
    /// Request to exchange a valid refresh token for a new access token.
    /// </summary>
    /// <param name="RefreshToken">The refresh token string.</param>
    public record RefreshTokenRequest(string RefreshToken);

    /// <summary>
    /// Request to exchange a trusted tenant's access token for the current tenant's tokens
    /// (silent app switch). The DPoP proof for the request travels in the DPoP header.
    /// </summary>
    /// <param name="SubjectToken">The DPoP-bound access token issued by a trusted tenant.</param>
    public record ExchangeTokenRequest(string SubjectToken);

    /// <summary>
    /// A standard structure for returning error messages.
    /// </summary>
    /// <param name="Message">The description of the error.</param>
    public record ErrorResponse(string Message);
}

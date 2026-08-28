using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using StackExchange.Redis;

namespace MyPassKeys;

public static class EmailVerificationEndpoints
{
    public static void MapEmailVerificationEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("auth/email");

        group.MapPost("request-verification", RequestVerification)
            .RequireRateLimiting("email");

        group.MapPost("verify", VerifyCode)
            .RequireRateLimiting("email");
    }

    private static async Task<IResult> RequestVerification(
        [FromBody] EmailVerificationRequest request,
        IConnectionMultiplexer redis,
        ITenantService tenantService,
        EmailService emailService,
        IFido2DbService fido2DbService,
        ILogger<EmailVerificationLog> logger)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(request.Email) || !request.Email.Contains('@'))
                return Results.BadRequest(new Fido2Endpoints.ErrorResponse("Valid email is required"));

            var email = request.Email.Trim().ToLowerInvariant();

            var tenant = await tenantService.GetCurrentTenantAsync();
            if (tenant == null)
                return Results.BadRequest(new Fido2Endpoints.ErrorResponse("Unknown tenant"));

            var db = redis.GetDatabase();
            var cooldownKey = $"EmailCooldown:{tenant.Id}:{email}";
            var codeKey = $"EmailCode:{tenant.Id}:{email}";

            // Always return the same generic response so callers cannot enumerate accounts
            // or distinguish "already registered" / "cooldown active" / "policy-rejected" from
            // "code sent". Every suppression branch below routes here.
            var genericResponse = Results.Ok(new { message = "If the email is eligible, a verification code has been sent." });

            // Per-tenant registration policy gate. Suppression is silent — leaking which emails
            // are pre-registered or which domains are allowed would defeat the point.
            var existingUser = await fido2DbService.GetUserByUsernameAsync(email);
            switch (tenant.RegistrationMode)
            {
                case RegistrationModes.DomainAllowlist:
                    if (!RegistrationPolicy.IsDomainAllowed(email, tenant.AllowedEmailDomains))
                    {
                        logger.LogInformation("Verification request rejected by domain allowlist for {Email}, tenant {TenantId}", email, tenant.Id);
                        return genericResponse;
                    }
                    // Always send — existing users may be recovering a lost passkey.
                    break;
                case RegistrationModes.InviteOnly:
                    if (existingUser == null)
                    {
                        logger.LogInformation("Verification request for uninvited email {Email}, tenant {TenantId}", email, tenant.Id);
                        return genericResponse;
                    }
                    // Invited user — always send (may be recovering a lost passkey).
                    break;
                default: // RegistrationModes.Open
                    // Always send — email ownership proves identity; this IS the recovery path.
                    break;
            }

            // Suppress send if a code was sent recently. Cooldown TTL still controls next eligible send.
            if (await db.KeyExistsAsync(cooldownKey))
            {
                logger.LogInformation("Verification request within cooldown for {Email}, tenant {TenantId}", email, tenant.Id);
                return genericResponse;
            }

            var code = RandomNumberGenerator.GetInt32(100000, 999999).ToString();
            await db.StringSetAsync(codeKey, code, TimeSpan.FromMinutes(10));
            await db.StringSetAsync(cooldownKey, "1", TimeSpan.FromSeconds(60));

            var sent = await emailService.SendVerificationCodeAsync(email, code, tenant.ServerName);
            if (!sent)
            {
                logger.LogWarning("Email verification failed for {Email}, could not send email", email);
                return Results.StatusCode(502); // Bad Gateway — upstream email service failed
            }

            logger.LogInformation("Verification code sent to {Email} for tenant {TenantId}", email, tenant.Id);
            return genericResponse;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error in RequestVerification");
            return Results.BadRequest(new Fido2Endpoints.ErrorResponse("Request failed"));
        }
    }

    private static async Task<IResult> VerifyCode(
        [FromBody] VerifyCodeRequest request,
        IConnectionMultiplexer redis,
        ITenantService tenantService,
        ILogger<EmailVerificationLog> logger)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Code))
                return Results.BadRequest(new Fido2Endpoints.ErrorResponse("Email and code are required"));

            var email = request.Email.Trim().ToLowerInvariant();

            var tenant = await tenantService.GetCurrentTenantAsync();
            if (tenant == null)
                return Results.BadRequest(new Fido2Endpoints.ErrorResponse("Unknown tenant"));

            var db = redis.GetDatabase();
            var codeKey = $"EmailCode:{tenant.Id}:{email}";
            var attemptsKey = $"EmailCodeAttempts:{tenant.Id}:{email}";
            const int maxAttempts = 5;

            // Atomically increment attempt counter; lock out after maxAttempts to prevent brute force
            // of the 6-digit code (1M combinations) by callers spread across many IPs.
            var attempts = await db.StringIncrementAsync(attemptsKey);
            if (attempts == 1)
                await db.KeyExpireAsync(attemptsKey, TimeSpan.FromMinutes(10));

            if (attempts > maxAttempts)
            {
                // Burn the code so further guesses are useless; force the user to request a new one.
                await db.KeyDeleteAsync(codeKey);
                logger.LogWarning("Verification code attempt limit exceeded for {Email}, tenant {TenantId}", email, tenant.Id);
                return Results.BadRequest(new Fido2Endpoints.ErrorResponse("Too many attempts. Request a new code."));
            }

            // Peek-and-delete-on-success rather than always-delete: a single typo shouldn't burn the code.
            var storedCode = await db.StringGetAsync(codeKey);
            if (!storedCode.HasValue)
                return Results.BadRequest(new Fido2Endpoints.ErrorResponse("Code expired or not found"));

            var storedBytes = Encoding.UTF8.GetBytes(storedCode.ToString());
            var providedBytes = Encoding.UTF8.GetBytes(request.Code);
            if (!CryptographicOperations.FixedTimeEquals(storedBytes, providedBytes))
            {
                logger.LogWarning("Invalid verification code for {Email}", email);
                return Results.BadRequest(new Fido2Endpoints.ErrorResponse("Invalid code"));
            }

            // Success: consume the code and reset attempt tracking.
            await db.KeyDeleteAsync(codeKey);
            await db.KeyDeleteAsync(attemptsKey);

            // Mark email as verified in Redis (30-min TTL — enough to complete passkey registration)
            var verifiedKey = $"EmailVerified:{tenant.Id}:{email}";
            await db.StringSetAsync(verifiedKey, "1", TimeSpan.FromMinutes(30));

            logger.LogInformation("Email verified: {Email} for tenant {TenantId}", email, tenant.Id);

            return Results.Ok(new { message = "Email verified", verified = true });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error in VerifyCode");
            return Results.BadRequest(new Fido2Endpoints.ErrorResponse("Request failed"));
        }
    }

    private class EmailVerificationLog;

    public record EmailVerificationRequest(string Email);
    public record VerifyCodeRequest(string Email, string Code);

}

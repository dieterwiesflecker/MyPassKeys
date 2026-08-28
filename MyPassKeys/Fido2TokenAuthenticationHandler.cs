using System.Text.Encodings.Web;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace MyPassKeys;

/// <summary>
/// only accepts DPop
/// </summary>
/// <param name="options"></param>
/// <param name="logger"></param>
/// <param name="encoder"></param>
/// <param name="tokenService"></param>
public class Fido2TokenAuthenticationHandler(
  IOptionsMonitor<AuthenticationSchemeOptions> options,
  ILoggerFactory logger,
  UrlEncoder encoder,
  TokenService tokenService)
  : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
  protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
  {
    // 1. Extract Header
    // RFC 9449 mandates the "DPoP" scheme.
    // We use AuthenticationHeaderValue for safer parsing than manual string manipulation.
    if (!AuthenticationHeaderValue.TryParse(Request.Headers.Authorization, out var headerValue) ||
        !"DPoP".Equals(headerValue.Scheme, StringComparison.OrdinalIgnoreCase))
    {
      return AuthenticateResult.NoResult();
    }

    var token = headerValue.Parameter;
    if (string.IsNullOrEmpty(token))
    {
      return AuthenticateResult.Fail("Token is missing.");
    }

    // 2. Extract Context for DPoP (Mandatory for strict DPoP enforcement)
    var dpopProof = Request.Headers["DPoP"].ToString();
    if (string.IsNullOrEmpty(dpopProof))
    {
      return AuthenticateResult.Fail("DPoP proof header is missing.");
    }

    var httpMethod = Request.Method;
    var httpUrl = $"{Request.Scheme}://{Request.Host}{Request.PathBase}{Request.Path}";

    // 3. Validate via TokenService
    var principal = await tokenService.ValidateTokenAsync(token, dpopProof, httpMethod, httpUrl);

    if (principal == null)
    {
      return AuthenticateResult.Fail("Invalid token or DPoP proof.");
    }

    // 4. Enforce DPoP Binding
    // ValidateTokenAsync might return a principal for a standard Bearer token if the 'cnf' claim is missing.
    // Since you "use only Dpop tokens", we must reject any token that doesn't have the 'cnf' claim.
    if (!principal.HasClaim(c => c.Type == "cnf"))
    {
      return AuthenticateResult.Fail("Access token is not DPoP-bound (missing 'cnf' claim).");
    }

    // 5. Success
    var ticket = new AuthenticationTicket(principal, Scheme.Name);
    return AuthenticateResult.Success(ticket);
  }
}
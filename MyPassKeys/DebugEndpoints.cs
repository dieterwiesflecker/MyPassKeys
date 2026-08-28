namespace MyPassKeys;

public static class DebugEndpoints
{
  public static void MapDebugEndpoints(this IEndpointRouteBuilder app)
  {
    // Remove RequireAuthorization to allow inspecting invalid/expired tokens without middleware blocking it
    var group = app.MapGroup("debug");

    group.MapGet("/token", (HttpContext context, TokenService tokenService) =>
    {
      // Manually extract the token from the Authorization header (Bearer/DPoP eyJ...)
      var token = context.Request.Headers.Authorization.ToString();
      if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        token = token["Bearer ".Length..].Trim();
      else if (token.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
        token = token["DPoP ".Length..].Trim();

      return Results.Ok(tokenService.InspectToken(token));
    });
  }
}

using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Data;

namespace SecureAuthMinimalApi.Endpoints;

public static class MfaDisableEndpoints
{
    public static void MapMfaDisable(this WebApplication app, ILogger logger)
    {
        app.MapPost("/mfa/disable", async (HttpContext ctx, UserRepository users) =>
        {
            var session = ctx.GetRequiredSession();
            var user = await users.GetByIdAsync(session.UserId, ctx.RequestAborted);
            if (user is null)
                return Results.NotFound();

            await users.ClearTotpSecretAsync(session.UserId, ctx.RequestAborted);
            logger.LogInformation("MFA disabilitata userId={UserId}", session.UserId);
            return Results.Ok(new { ok = true });
        });
    }
}

using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Utilities;
namespace SecureAuthMinimalApi.Endpoints;

public static class MfaSetupEndpoints
{
    /// <summary>
    /// Mappa l'endpoint di setup MFA che genera e restituisce il segreto TOTP.
    /// </summary>
    public static void MapMfaSetup(this WebApplication app)
    {
        app.MapPost("/mfa/setup", async (HttpContext ctx, UserRepository users) =>
        {
            var session = ctx.GetRequiredSession();
            var user = await users.GetByIdAsync(session.UserId, ctx.RequestAborted);
            if (user is null)
                return Results.NotFound();

            if (!string.IsNullOrWhiteSpace(user.TotpSecret))
                return Results.StatusCode(StatusCodes.Status409Conflict);

            var secretKey = OtpNet.KeyGeneration.GenerateRandomKey(20);
            var secretBase32 = OtpNet.Base32Encoding.ToString(secretKey);

            await users.SetTotpSecretAsync(user.Id, secretBase32, ctx.RequestAborted);

            var issuer = Uri.EscapeDataString("SecureAuthMinimalApi");
            var label = Uri.EscapeDataString(user.Username);
            var otpauth = $"otpauth://totp/{issuer}:{label}?secret={secretBase32}&issuer={issuer}";

            return Results.Ok(new { ok = true, secret = secretBase32, otpauthUri = otpauth });
        });
    }
}

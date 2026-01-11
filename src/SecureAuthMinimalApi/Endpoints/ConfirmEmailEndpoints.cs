using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Logging;

namespace SecureAuthMinimalApi.Endpoints;

public static class ConfirmEmailEndpoints
{
    /// <summary>
    /// Mappa l'endpoint di conferma email che valida il token e marca l'utente come confermato.
    /// </summary>
    public static void MapConfirmEmail(this WebApplication app)
    {
        app.MapPost("/confirm-email", async (HttpContext ctx, UserRepository users, ILogger<ConfirmEmailLogger> logger) =>
        {
            var req = await ctx.Request.ReadFromJsonAsync<ConfirmEmailRequest>();
            if (string.IsNullOrWhiteSpace(req?.Token))
            {
                logger.LogWarning("Conferma email fallita: token mancante");
                return Results.BadRequest(new { ok = false, error = "invalid_input", errors = new[] { "token_required" } });
            }
            else
            {
                logger.LogInformation("Conferma email richiesta token={Token}", req.Token);
            }

            var user = await users.GetByEmailTokenAsync(req.Token, ctx.RequestAborted);
            if (user is null)
            {
                logger.LogWarning("Conferma email fallita: token non trovato token={Token}", req.Token);
                return Results.BadRequest(new { ok = false, error = "invalid_token" });
            }
            logger.LogInformation("Conferma email: utente trovato userId={UserId} emailConfirmed={EmailConfirmed} tokenExp={TokenExp}", user.Id, user.EmailConfirmed, user.EmailConfirmExpiresUtc);

            if (user.EmailConfirmed)
            {
                logger.LogInformation("Email gia confermata userId={UserId}", user.Id);
                await users.ConfirmEmailAsync(user.Id, ctx.RequestAborted);
                return Results.Ok(new { ok = true, alreadyConfirmed = true });
            }

            if (string.IsNullOrWhiteSpace(user.EmailConfirmExpiresUtc) || DateTime.Parse(user.EmailConfirmExpiresUtc).ToUniversalTime() <= DateTime.UtcNow)
            {
                logger.LogWarning("Conferma email fallita: token scaduto userId={UserId} token={Token} exp={Exp}", user.Id, user.EmailConfirmToken, user.EmailConfirmExpiresUtc);
                return Results.Json(new { ok = false, error = "token_expired" }, statusCode: StatusCodes.Status410Gone);
            }

            await users.ConfirmEmailAsync(user.Id, ctx.RequestAborted);
            logger.LogInformation("Email confermata userId={UserId}", user.Id);
            return Results.Ok(new { ok = true });
        });
    }
}

using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Services;
using static SecureAuthMinimalApi.Endpoints.EndpointUtilities;

namespace SecureAuthMinimalApi.Endpoints;

/// <summary>
/// Endpoint per cambiare email a un account non confermato (richiede sessione autenticata).
/// </summary>
public static class ChangeEmailEndpoints
{
    public static void MapChangeEmail(this WebApplication app, ILogger logger)
    {
        var env = app.Environment;

        app.MapPost("/me/email", async (HttpContext ctx, UserRepository users, IEmailService emailService) =>
        {
            var req = await ctx.Request.ReadFromJsonAsync<ChangeEmailRequest>();
            var newEmailRaw = req?.NewEmail;
            if (string.IsNullOrWhiteSpace(newEmailRaw))
            {
                return Results.BadRequest(new { ok = false, error = "invalid_input" });
            }

            var normalized = NormalizeEmail(newEmailRaw);
            if (string.IsNullOrWhiteSpace(normalized) || !normalized.Contains('@'))
            {
                return Results.BadRequest(new { ok = false, error = "email_invalid" });
            }

            var session = ctx.GetRequiredSession();
            var user = await users.GetByIdAsync(session.UserId, ctx.RequestAborted);
            if (user is null)
            {
                return Results.Unauthorized();
            }

            if (user.EmailConfirmed)
            {
                return Results.BadRequest(new { ok = false, error = "email_already_confirmed" });
            }

            if (string.Equals(user.EmailNormalized, normalized, StringComparison.OrdinalIgnoreCase))
            {
                return Results.BadRequest(new { ok = false, error = "email_unchanged" });
            }

            var conflict = await users.GetByEmailAsync(normalized, ctx.RequestAborted);
            if (conflict is not null && !string.Equals(conflict.Id, user.Id, StringComparison.Ordinal))
            {
                return Results.StatusCode(StatusCodes.Status409Conflict);
            }

            var confirmToken = Guid.NewGuid().ToString("N");
            var confirmExp = DateTime.UtcNow.AddHours(24).ToString("O");
            await users.UpdateEmailAsync(user.Id, newEmailRaw.Trim(), normalized, confirmToken, confirmExp, ctx.RequestAborted);

            try
            {
                await emailService.SendEmailConfirmationAsync(newEmailRaw.Trim(), confirmToken, confirmExp);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Errore invio email conferma per cambio email userId={UserId}", user.Id);
            }

            if (env.IsDevelopment())
            {
                return Results.Ok(new { ok = true, confirmToken, confirmExpiresUtc = confirmExp });
            }

            return Results.Ok(new { ok = true });
        });
    }
}

internal sealed record ChangeEmailRequest(string? NewEmail);

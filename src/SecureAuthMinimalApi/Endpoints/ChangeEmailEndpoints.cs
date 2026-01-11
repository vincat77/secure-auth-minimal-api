using SecureAuthMinimalApi.Data;
using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Services;
using SecureAuthMinimalApi.Filters;
using SecureAuthMinimalApi.Utilities;
using SecureAuthMinimalApi.Models;
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
            var emailInput = await ctx.ReadAndValidateEmailAsync(logger);
            if (emailInput.ErrorResult is not null)
                return emailInput.ErrorResult;

            var session = ctx.GetRequiredSession();
            var user = await users.GetByIdAsync(session.UserId, ctx.RequestAborted);
            if (user is null)
                return Results.Unauthorized();

            var eligibility = await users.EnsureUserEligibleAsync(user, emailInput.Normalized!, ctx.RequestAborted);
            if (eligibility is not null)
                return eligibility;

            return await UpdateAndSendConfirmationAsync(
                users,
                emailService,
                user,
                emailInput.Raw!,
                emailInput.Normalized!,
                env.IsDevelopment(),
                logger,
                ctx.RequestAborted);
        })
        .RequireSession()
        .RequireCsrf();
    }

    private static async Task<(string? Raw, string? Normalized, IResult? ErrorResult)> ReadAndValidateEmailAsync(this HttpContext ctx, ILogger logger)
    {
        var req = await ctx.Request.ReadFromJsonAsync<ChangeEmailRequest>();
        var newEmailRaw = req?.NewEmail;
        if (string.IsNullOrWhiteSpace(newEmailRaw))
        {
            return (null, null, Results.BadRequest(new { ok = false, error = "invalid_input" }));
        }

        var normalized = NormalizeEmail(newEmailRaw);
        if (string.IsNullOrWhiteSpace(normalized) || !normalized.Contains('@'))
        {
            return (null, null, Results.BadRequest(new { ok = false, error = "email_invalid" }));
        }

        logger.LogDebug("Cambio email: input normalizzato {Email}", normalized);
        return (newEmailRaw, normalized, null);
    }

    private static async Task<IResult?> EnsureUserEligibleAsync(this UserRepository users, User user, string normalizedEmail, CancellationToken ct)
    {
        if (user.EmailConfirmed)
        {
            return Results.BadRequest(new { ok = false, error = "email_already_confirmed" });
        }

        if (string.Equals(user.EmailNormalized, normalizedEmail, StringComparison.OrdinalIgnoreCase))
        {
            return Results.BadRequest(new { ok = false, error = "email_unchanged" });
        }

        var conflict = await users.GetByEmailAsync(normalizedEmail, ct);
        if (conflict is not null && !string.Equals(conflict.Id, user.Id, StringComparison.Ordinal))
        {
            return Results.StatusCode(StatusCodes.Status409Conflict);
        }

        return null;
    }

    private static async Task<IResult> UpdateAndSendConfirmationAsync(
        UserRepository users,
        IEmailService emailService,
        User user,
        string rawEmail,
        string normalizedEmail,
        bool isDevelopment,
        ILogger logger,
        CancellationToken ct)
    {
        var confirmToken = Guid.NewGuid().ToString("N");
        var confirmExp = DateTime.UtcNow.AddHours(24).ToString("O");
        await users.UpdateEmailAsync(user.Id, rawEmail.Trim(), normalizedEmail, confirmToken, confirmExp, ct);

        try
        {
            await emailService.SendEmailConfirmationAsync(rawEmail.Trim(), confirmToken, confirmExp);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Errore invio email conferma per cambio email userId={UserId}", user.Id);
        }

        if (isDevelopment)
        {
            return Results.Ok(new { ok = true, confirmToken, confirmExpiresUtc = confirmExp });
        }

        return Results.Ok(new { ok = true });
    }
}

internal sealed record ChangeEmailRequest(string? NewEmail);

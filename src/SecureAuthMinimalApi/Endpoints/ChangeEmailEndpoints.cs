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

            var context = new EmailChangeContext(
                Users: users,
                EmailService: emailService,
                User: user,
                RawEmail: emailInput.Raw!,
                NormalizedEmail: emailInput.Normalized!,
                IsDevelopment: env.IsDevelopment(),
                Logger: logger,
                CancellationToken: ctx.RequestAborted);

            return await UpdateAndSendConfirmationAsync(context);
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

    private static async Task<IResult> UpdateAndSendConfirmationAsync(EmailChangeContext context)
    {
        var confirmToken = Guid.NewGuid().ToString("N");
        var confirmExp = DateTime.UtcNow.AddHours(24).ToString("O");
        await context.Users.UpdateEmailAsync(context.User.Id, context.RawEmail.Trim(), context.NormalizedEmail, confirmToken, confirmExp, context.CancellationToken);

        try
        {
            await context.EmailService.SendEmailConfirmationAsync(context.RawEmail.Trim(), confirmToken, confirmExp);
        }
        catch (Exception ex)
        {
            context.Logger.LogError(ex, "Errore invio email conferma per cambio email userId={UserId}", context.User.Id);
        }

        if (context.IsDevelopment)
        {
            return Results.Ok(new { ok = true, confirmToken, confirmExpiresUtc = confirmExp });
        }

        return Results.Ok(new { ok = true });
    }
}

internal sealed record ChangeEmailRequest(string? NewEmail);

internal readonly record struct EmailChangeContext(
    UserRepository Users,
    IEmailService EmailService,
    User User,
    string RawEmail,
    string NormalizedEmail,
    bool IsDevelopment,
    ILogger Logger,
    CancellationToken CancellationToken);

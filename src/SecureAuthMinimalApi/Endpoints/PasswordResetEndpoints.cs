using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using static SecureAuthMinimalApi.Endpoints.EndpointUtilities;

namespace SecureAuthMinimalApi.Endpoints;

/// <summary>
/// Endpoint MVP per richiesta/conferma reset password (solo logica base, token restituito solo in dev/test se configurato).
/// </summary>
public static class PasswordResetEndpoints
{
    public static void MapPasswordReset(this WebApplication app, ILogger logger, bool requireConfirmed, int expirationMinutes, bool includeTokenInResponseForTesting)
    {
        app.MapPost("/password-reset/request", async (HttpContext ctx, UserRepository users, PasswordResetRepository resets) =>
        {
            var req = await ctx.Request.ReadFromJsonAsync<PasswordResetRequest>();
            if (string.IsNullOrWhiteSpace(req?.Email))
            {
                return Results.BadRequest(new { ok = false, error = "invalid_input" });
            }

            var email = NormalizeEmail(req.Email);
            if (string.IsNullOrWhiteSpace(email))
            {
                return Results.BadRequest(new { ok = false, error = "invalid_input" });
            }

            var user = await users.GetByEmailAsync(email!, ctx.RequestAborted);
            if (user is null)
            {
                logger.LogInformation("Password reset request per email non trovata {Email}", email);
                return Results.Ok(new { ok = true });
            }

            if (requireConfirmed && !user.EmailConfirmed)
            {
                logger.LogInformation("Password reset bloccato: email non confermata userId={UserId}", user.Id);
                return Results.Ok(new { ok = true });
            }

            var now = DateTime.UtcNow;
            var expires = now.AddMinutes(expirationMinutes <= 0 ? 30 : expirationMinutes);
            var token = GenerateToken();
            var tokenHash = HashToken(token);
            var reset = new PasswordReset
            {
                Id = Guid.NewGuid().ToString("N"),
                UserId = user.Id,
                TokenHash = tokenHash,
                ExpiresAtUtc = expires.ToString("O"),
                UsedAtUtc = null,
                CreatedAtUtc = now.ToString("O"),
                ClientIp = ctx.Connection.RemoteIpAddress?.ToString(),
                UserAgent = ctx.Request.Headers["User-Agent"].ToString()
            };

            await resets.InvalidatePreviousForUserAsync(user.Id, now.ToString("O"), ctx.RequestAborted);
            await resets.CreateAsync(reset, ctx.RequestAborted);
            logger.LogInformation("Password reset creato userId={UserId} exp={Exp}", user.Id, reset.ExpiresAtUtc);

            if (includeTokenInResponseForTesting)
            {
                return Results.Ok(new { ok = true, resetToken = token });
            }

            return Results.Ok(new { ok = true });
        });

        app.MapPost("/password-reset/confirm", async (HttpContext ctx, UserRepository users, PasswordResetRepository resets, SessionRepository sessions, RefreshTokenRepository refreshRepo) =>
        {
            var req = await ctx.Request.ReadFromJsonAsync<PasswordResetConfirmRequest>();
            if (string.IsNullOrWhiteSpace(req?.Token) || string.IsNullOrWhiteSpace(req.NewPassword) || string.IsNullOrWhiteSpace(req.ConfirmPassword) || !string.Equals(req.NewPassword, req.ConfirmPassword, StringComparison.Ordinal))
            {
                return Results.BadRequest(new { ok = false, error = "invalid_input" });
            }

            var tokenHash = HashToken(req.Token!);
            var reset = await resets.GetByTokenHashAsync(tokenHash, ctx.RequestAborted);
            if (reset is null || !DateTime.TryParse(reset.ExpiresAtUtc, out var exp) || exp.ToUniversalTime() <= DateTime.UtcNow || !string.IsNullOrWhiteSpace(reset.UsedAtUtc))
            {
                return Results.BadRequest(new { ok = false, error = "invalid_token" });
            }

            var user = await users.GetByIdAsync(reset.UserId, ctx.RequestAborted);
            if (user is null)
            {
                return Results.BadRequest(new { ok = false, error = "invalid_token" });
            }

            var cfg = ctx.RequestServices.GetRequiredService<IConfiguration>();
            var minLength = cfg.GetValue<int?>("PasswordPolicy:MinLength") ?? 12;
            var requireUpper = cfg.GetValue<bool?>("PasswordPolicy:RequireUpper") ?? false;
            var requireLower = cfg.GetValue<bool?>("PasswordPolicy:RequireLower") ?? false;
            var requireDigit = cfg.GetValue<bool?>("PasswordPolicy:RequireDigit") ?? false;
            var requireSymbol = cfg.GetValue<bool?>("PasswordPolicy:RequireSymbol") ?? false;
            var policyErrors = AuthHelpers.ValidatePassword(req.NewPassword!, minLength, requireUpper, requireLower, requireDigit, requireSymbol);
            if (policyErrors.Any())
            {
                return Results.BadRequest(new { ok = false, error = "password_policy_failed", errors = policyErrors });
            }

            if (Services.PasswordHasher.Verify(req.NewPassword!, user.PasswordHash))
            {
                return Results.BadRequest(new { ok = false, error = "password_must_be_different" });
            }

            var used = await resets.MarkUsedAsync(reset.Id, DateTime.UtcNow.ToString("O"), ctx.RequestAborted);
            if (used == 0)
            {
                return Results.BadRequest(new { ok = false, error = "invalid_token" });
            }

            var newHash = Services.PasswordHasher.Hash(req.NewPassword!);
            await users.UpdatePasswordAsync(user.Id, newHash, ctx.RequestAborted);
            var nowIso = DateTime.UtcNow.ToString("O");
            await sessions.RevokeAllForUserAsync(user.Id, nowIso, ctx.RequestAborted);
            await refreshRepo.RevokeAllForUserAsync(user.Id, "password_reset", ctx.RequestAborted);
            logger.LogInformation("Password reset completato userId={UserId}", user.Id);
            return Results.Ok(new { ok = true });
        });
    }

    private static string GenerateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string HashToken(string token)
    {
        using var sha = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = sha.ComputeHash(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Services;
using SecureAuthMinimalApi.Options;
using Microsoft.Extensions.Options;
using static SecureAuthMinimalApi.Endpoints.EndpointUtilities;

namespace SecureAuthMinimalApi.Endpoints;

    /// <summary>
    /// Endpoint MVP per richiesta/conferma reset password (token restituito solo in dev/test se configurato).
    /// Richiede email confermata se configurato, risponde sempre 200 alla request per evitare enumeration
    /// e usa hash del token in DB. La conferma è transazionale e revoca sessioni/refresh.
    /// </summary>
    public static class PasswordResetEndpoints
    {
        public static void MapPasswordReset(this WebApplication app, ILogger logger)
        {
            var resetConfig = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<PasswordResetConfig>>().Value;
            var env = app.Services.GetRequiredService<IHostEnvironment>();
            var includeTokenInResponse = resetConfig.IncludeTokenInResponseForTesting && env.IsDevelopment();
            var rateLimitEnabled = resetConfig.RateLimitRequests > 0 && resetConfig.RateLimitWindowMinutes > 0;
            var rateLimitWindow = TimeSpan.FromMinutes(resetConfig.RateLimitWindowMinutes <= 0 ? 15 : resetConfig.RateLimitWindowMinutes);
            var connStrings = app.Services.GetRequiredService<IOptions<ConnectionStringsOptions>>().Value;
            var sqliteConnString = connStrings.Sqlite
                ?? throw new InvalidOperationException("Missing ConnectionStrings:Sqlite for password reset");

            app.MapPost("/password-reset/request", async (HttpContext ctx, UserRepository users, PasswordResetRepository resets, IEmailService emailService) =>
            {
                // Input essenziale: email normalizzata; risposta sempre 200 per non leakare esistenza account/stato conferma.
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

            if (rateLimitEnabled)
            {
                var clientIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "noip";
                var key = $"{email}|{clientIp}";
                if (RateLimiter.ShouldThrottle(key, resetConfig.RateLimitRequests, rateLimitWindow))
                {
                    return Results.StatusCode(StatusCodes.Status429TooManyRequests);
                }
            }

            var user = await users.GetByEmailAsync(email!, ctx.RequestAborted);
            if (user is null)
            {
                logger.LogInformation("Password reset request per email non trovata {Email}", email);
                return Results.Ok(new { ok = true });
            }

            if (!string.IsNullOrWhiteSpace(user.DeletedAtUtc))
            {
                logger.LogInformation("Password reset bloccato: utente cancellato userId={UserId}", user.Id);
                return Results.Ok(new { ok = true });
            }

            if (user.IsLocked)
            {
                logger.LogInformation("Password reset bloccato: account locked userId={UserId}", user.Id);
                return Results.Ok(new { ok = true });
            }

            if (resetConfig.RequireConfirmed && !user.EmailConfirmed)
            {
                var confirmToken = string.IsNullOrWhiteSpace(user.EmailConfirmToken)
                    ? Guid.NewGuid().ToString("N")
                    : user.EmailConfirmToken!;
                var confirmExp = string.IsNullOrWhiteSpace(user.EmailConfirmExpiresUtc)
                    ? DateTime.UtcNow.AddHours(24)
                    : DateTime.Parse(user.EmailConfirmExpiresUtc).ToUniversalTime();
                if (confirmExp <= DateTime.UtcNow)
                {
                    confirmExp = DateTime.UtcNow.AddHours(24);
                }

                await users.UpdateEmailConfirmTokenAsync(user.Id, confirmToken, confirmExp.ToString("O"), ctx.RequestAborted);
                if (!string.IsNullOrWhiteSpace(user.Email))
                {
                    try
                    {
                        await emailService.SendEmailConfirmationAsync(user.Email!, confirmToken, confirmExp.ToString("O"));
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Errore invio email conferma per reset bloccato userId={UserId}", user.Id);
                    }
                }

                logger.LogInformation("Password reset bloccato: email non confermata userId={UserId}, token di conferma (ri)inviato", user.Id);
                return Results.Ok(new { ok = true });
            }

            var now = DateTime.UtcNow;
            var expMinutes = resetConfig.ExpirationMinutes <= 0 ? 30 : resetConfig.ExpirationMinutes;
            var expires = now.AddMinutes(expMinutes);
            var token = GenerateToken();
            var tokenHash = SecurityUtils.HashToken(token);
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

            if (includeTokenInResponse)
            {
                return Results.Ok(new { ok = true, resetToken = token });
            }

            if (!string.IsNullOrWhiteSpace(user.Email))
            {
                try
                {
                    await emailService.SendPasswordResetEmailAsync(user.Email!, token, reset.ExpiresAtUtc);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Errore durante l'invio email reset password userId={UserId}", user.Id);
                }
            }

            return Results.Ok(new { ok = true });
        });

        app.MapPost("/password-reset/confirm", async (HttpContext ctx, UserRepository users, PasswordResetRepository resets, SessionRepository sessions, RefreshTokenRepository refreshRepo) =>
        {
            // Valida payload; rifiuta token vuoti e mismatch password con 400 uniforme.
            var req = await ctx.Request.ReadFromJsonAsync<PasswordResetConfirmRequest>();
            if (string.IsNullOrWhiteSpace(req?.Token) || string.IsNullOrWhiteSpace(req.NewPassword) || string.IsNullOrWhiteSpace(req.ConfirmPassword) || !string.Equals(req.NewPassword, req.ConfirmPassword, StringComparison.Ordinal))
            {
                return Results.BadRequest(new { ok = false, error = "invalid_input" });
            }

            var tokenHash = SecurityUtils.HashToken(req.Token!);
            var reset = await resets.GetByTokenHashAsync(tokenHash, ctx.RequestAborted);
            if (reset is null || !DateTime.TryParse(reset.ExpiresAtUtc, out var exp) || exp.ToUniversalTime() <= DateTime.UtcNow || !string.IsNullOrWhiteSpace(reset.UsedAtUtc))
            {
                return Results.BadRequest(new { ok = false, error = "invalid_token" });
            }

            var user = await users.GetByIdAsync(reset.UserId, ctx.RequestAborted);
            if (user is null || string.IsNullOrWhiteSpace(user.EmailNormalized))
            {
                return Results.BadRequest(new { ok = false, error = "invalid_token" });
            }

            if (!string.IsNullOrWhiteSpace(user.DeletedAtUtc))
            {
                return Results.BadRequest(new { ok = false, error = "invalid_token" });
            }

            if (user.IsLocked)
            {
                return Results.BadRequest(new { ok = false, error = "account_locked" });
            }

            var passwordOptions = ctx.RequestServices.GetRequiredService<IOptions<PasswordPolicyOptions>>().Value;
            var minLength = passwordOptions.MinLength < 1 ? 12 : passwordOptions.MinLength;
            var policyErrors = AuthHelpers.ValidatePassword(req.NewPassword!, minLength, passwordOptions.RequireUpper, passwordOptions.RequireLower, passwordOptions.RequireDigit, passwordOptions.RequireSymbol);
            if (policyErrors.Any())
            {
                return Results.BadRequest(new { ok = false, error = "password_policy_failed", errors = policyErrors });
            }

            if (Services.PasswordHasher.Verify(req.NewPassword!, user.PasswordHash))
            {
                return Results.BadRequest(new { ok = false, error = "password_must_be_different" });
            }

            var newHash = Services.PasswordHasher.Hash(req.NewPassword!);
            var nowIso = DateTime.UtcNow.ToString("O");

            // Transazione best-effort: MarkUsed + Update password + revoke session/refresh.
            await using var db = new Microsoft.Data.Sqlite.SqliteConnection(sqliteConnString);
            await db.OpenAsync(ctx.RequestAborted);
            await using var tx = await db.BeginTransactionAsync(ctx.RequestAborted);
            try
            {
                var used = await resets.MarkUsedAsync(reset.Id, nowIso, ctx.RequestAborted, tx, db);
                if (used == 0)
                {
                    await tx.RollbackAsync(ctx.RequestAborted);
                    return Results.BadRequest(new { ok = false, error = "invalid_token" });
                }

                await users.UpdatePasswordAsync(user.Id, newHash, ctx.RequestAborted, db, tx);
                await sessions.RevokeAllForUserAsync(user.Id, nowIso, ctx.RequestAborted, db, tx);
                await refreshRepo.RevokeAllForUserAsync(user.Id, "password_reset", ctx.RequestAborted, db, tx);

                await tx.CommitAsync(ctx.RequestAborted);
            }
            catch
            {
                await tx.RollbackAsync(ctx.RequestAborted);
                throw;
            }

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

    private static class RateLimiter
    {
        private static readonly ConcurrentDictionary<string, ConcurrentQueue<DateTime>> Buckets = new(StringComparer.OrdinalIgnoreCase);

        public static bool ShouldThrottle(string key, int limit, TimeSpan window)
        {
            if (limit <= 0)
                return false;

            var queue = Buckets.GetOrAdd(key, _ => new ConcurrentQueue<DateTime>());
            var now = DateTime.UtcNow;

            while (queue.TryPeek(out var ts) && now - ts > window)
            {
                queue.TryDequeue(out _);
            }

            if (queue.Count >= limit)
                return true;

            queue.Enqueue(now);
            return false;
        }
    }
}

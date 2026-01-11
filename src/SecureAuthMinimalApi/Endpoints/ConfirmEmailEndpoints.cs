using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Logging;
using SecureAuthMinimalApi.Options;
using SecureAuthMinimalApi.Utilities;
using Microsoft.Extensions.Options;
using static SecureAuthMinimalApi.Endpoints.EndpointUtilities;

namespace SecureAuthMinimalApi.Endpoints;

public static class ConfirmEmailEndpoints
{
    /// <summary>
    /// Mappa l'endpoint di conferma email che valida il token e marca l'utente come confermato.
    /// </summary>
    public static void MapConfirmEmail(this WebApplication app)
    {
        var rateLimitOptions = app.Services.GetRequiredService<IOptions<ConfirmEmailRateLimitOptions>>().Value;

        app.MapPost("/confirm-email", async (HttpContext ctx, UserRepository users, IOptions<TokenHashingOptions> tokenHashing, ILogger<ConfirmEmailLogger> logger) =>
        {
            if (IsConfirmRateLimited(ctx, rateLimitOptions))
            {
                logger.LogWarning("Conferma email rate-limit superato per IP {Ip}", GetClientIp(ctx));
                return Results.StatusCode(StatusCodes.Status429TooManyRequests);
            }

            var req = await ctx.Request.ReadFromJsonAsync<ConfirmEmailRequest>();
            if (string.IsNullOrWhiteSpace(req?.Token))
            {
                logger.LogWarning("Conferma email fallita: token mancante");
                return Results.BadRequest(new { ok = false, error = "invalid_input", errors = new[] { "token_required" } });
            }

            string tokenHash;
            try
            {
                tokenHash = TokenHasher.HmacSha256Base64Url(tokenHashing.Value.EmailConfirmPepper, req.Token);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Errore hashing token conferma email");
                return Results.BadRequest(new { ok = false, error = "invalid_token" });
            }

            var user = await users.GetByEmailTokenHashAsync(tokenHash, ctx.RequestAborted);
            if (user is null)
            {
                user = await users.GetByEmailTokenLegacyAsync(req.Token, ctx.RequestAborted);
            }
            if (user is null)
            {
                logger.LogWarning("Conferma email fallita: token non trovato");
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
                logger.LogWarning("Conferma email fallita: token scaduto userId={UserId} exp={Exp}", user.Id, user.EmailConfirmExpiresUtc);
                return Results.Json(new { ok = false, error = "token_expired" }, statusCode: StatusCodes.Status410Gone);
            }

            await users.ConfirmEmailAsync(user.Id, ctx.RequestAborted);
            logger.LogInformation("Email confermata userId={UserId}", user.Id);
            return Results.Ok(new { ok = true });
        });
    }

    private static bool IsConfirmRateLimited(HttpContext ctx, ConfirmEmailRateLimitOptions options)
    {
        if (options.Requests <= 0)
            return false;

        var window = options.WindowMinutes <= 0 ? TimeSpan.FromMinutes(1) : TimeSpan.FromMinutes(options.WindowMinutes);
        var ip = GetClientIp(ctx);
        return ConfirmRateLimiter.ShouldThrottle(ip, options.Requests, window);
    }

    private static class ConfirmRateLimiter
    {
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, System.Collections.Concurrent.ConcurrentQueue<DateTime>> Store = new();

        public static bool ShouldThrottle(string key, int maxRequests, TimeSpan window)
        {
            var now = DateTime.UtcNow;
            var queue = Store.GetOrAdd(key, _ => new System.Collections.Concurrent.ConcurrentQueue<DateTime>());
            queue.Enqueue(now);

            while (queue.TryPeek(out var ts) && ts < now - window)
            {
                queue.TryDequeue(out _);
            }

            return queue.Count > maxRequests;
        }
    }
}

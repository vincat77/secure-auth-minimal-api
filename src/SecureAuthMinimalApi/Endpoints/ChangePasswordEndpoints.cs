using System.Text.Json;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Services;
using SecureAuthMinimalApi.Options;
using SecureAuthMinimalApi.Filters;
using SecureAuthMinimalApi.Logging;
using SecureAuthMinimalApi.Utilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static SecureAuthMinimalApi.Utilities.SecurityUtils;

namespace SecureAuthMinimalApi.Endpoints;

/// <summary>
/// Espone l'endpoint per il cambio password dell'utente autenticato.
/// </summary>
public static class ChangePasswordEndpoints
{
    /// <summary>
    /// Mappa l'endpoint /me/password con tutta la logica di validazione e rotazione sessione.
    /// </summary>
    public static void MapChangePassword(this WebApplication app)
    {
        app.MapPost("/me/password", async (
            HttpContext ctx,
            JwtTokenService jwt,
            SessionRepository sessions,
            UserRepository users,
            RefreshTokenRepository refreshRepo,
            IOptions<PasswordPolicyOptions> passwordPolicyOptions,
            IOptions<RememberMeOptions> rememberOptions,
            IOptions<CookieConfigOptions> cookieOptions,
            IWebHostEnvironment env,
            ILogger<ChangePasswordLoggerMarker> logger) =>
        {
            var policy = passwordPolicyOptions.Value;
            var body = await ctx.Request.ReadFromJsonAsync<ChangePasswordRequest>();
            var current = body?.CurrentPassword ?? "";
            var newPassword = body?.NewPassword ?? "";
            var confirm = body?.ConfirmPassword ?? "";

            var inputErrors = new List<string>();
            if (string.IsNullOrWhiteSpace(current))
                inputErrors.Add("current_required");
            if (string.IsNullOrWhiteSpace(newPassword))
                inputErrors.Add("new_required");
            if (string.IsNullOrWhiteSpace(confirm))
                inputErrors.Add("confirm_required");
            if (inputErrors.Any())
                return Results.BadRequest(new ChangePasswordResponse(false, "invalid_input", inputErrors));

            var session = ctx.GetRequiredSession();
            var user = await users.GetByIdAsync(session.UserId, ctx.RequestAborted);
            if (user is null)
            {
                logger.LogWarning("Cambio password fallito: utente non trovato userId={UserId}", session.UserId);
                return Results.Unauthorized();
            }

            if (!PasswordHasher.Verify(current.Trim(), user.PasswordHash))
            {
                logger.LogWarning("Cambio password fallito: current errata userId={UserId}", user.Id);
                return Results.BadRequest(new ChangePasswordResponse(false, "invalid_current_password"));
            }

            if (!string.Equals(newPassword, confirm, StringComparison.Ordinal))
            {
                logger.LogWarning("Cambio password fallito: mismatch conferma userId={UserId}", user.Id);
                return Results.BadRequest(new ChangePasswordResponse(false, "password_mismatch"));
            }

            if (PasswordHasher.Verify(newPassword, user.PasswordHash))
            {
                logger.LogWarning("Cambio password fallito: nuova password uguale alla precedente userId={UserId}", user.Id);
                return Results.BadRequest(new ChangePasswordResponse(false, "password_reused"));
            }

            var policyErrors = AuthHelpers.ValidatePassword(newPassword.Trim(), policy.EffectiveMinLength, policy.RequireUpper, policy.RequireLower, policy.RequireDigit, policy.RequireSymbol);
            if (policyErrors.Any())
            {
                logger.LogWarning("Cambio password fallito: policy non rispettata userId={UserId} errors={Errors}", user.Id, string.Join(",", policyErrors));
                return Results.BadRequest(new ChangePasswordResponse(false, "password_policy_failed", policyErrors));
            }

            var newHash = PasswordHasher.Hash(newPassword.Trim());
            await users.UpdatePasswordAsync(user.Id, newHash, ctx.RequestAborted);

            var nowIso = DateTime.UtcNow.ToString("O");
            await refreshRepo.RevokeAllForUserAsync(user.Id, "password_change", ctx.RequestAborted);
            await sessions.RevokeAllForUserAsync(user.Id, nowIso, ctx.RequestAborted);

            var sessionId = Guid.NewGuid().ToString("N");
            var csrfToken = Base64Url(RandomBytes(32));
            var (accessToken, expiresUtc) = jwt.CreateAccessToken(sessionId);
            var expIso = expiresUtc.ToString("O");

            var newSession = new UserSession
            {
                SessionId = sessionId,
                UserId = user.Id,
                CreatedAtUtc = nowIso,
                ExpiresAtUtc = expIso,
                RevokedAtUtc = null,
                UserDataJson = JsonSerializer.Serialize(new
                {
                    username = user.Username,
                    name = user.Name,
                    given_name = user.GivenName,
                    family_name = user.FamilyName,
                    email = user.Email,
                    picture = user.PictureUrl
                }),
                CsrfToken = csrfToken,
                LastSeenUtc = nowIso
            };

            await sessions.CreateAsync(newSession, ctx.RequestAborted);
            logger.LogInformation("Cambio password OK: sessione ruotata userId={UserId} nuovaSessione={SessionId}", user.Id, sessionId);

            var requireSecureConfig = rememberOptions.Value.RequireSecure || cookieOptions.Value.RequireSecure;
            var requireSecure = env.IsDevelopment() ? requireSecureConfig : true;
            if (!env.IsDevelopment() && !requireSecureConfig)
            {
                logger.LogWarning("Cookie Secure forzato in ambiente non Development, ignorando Cookie:RequireSecure=false");
            }

            ctx.Response.Cookies.Append(
                "access_token",
                accessToken,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = requireSecure,
                    SameSite = SameSiteMode.Strict,
                    Path = "/",
                    MaxAge = expiresUtc - DateTime.UtcNow
                });

            // Invalida eventuale refresh token esistente sul client.
            var refreshCookieName = rememberOptions.Value.CookieName ?? "refresh_token";
            var refreshPath = rememberOptions.Value.Path ?? "/refresh";
            var rememberSameSite = ParseSameSite(rememberOptions.Value.SameSite, rememberOptions.Value.AllowSameSiteNone, env.IsDevelopment(), logger, "RememberMe");
            ctx.Response.Cookies.Append(refreshCookieName, "", new CookieOptions
            {
                Expires = DateTimeOffset.UnixEpoch,
                HttpOnly = true,
                Secure = requireSecure,
                SameSite = rememberSameSite,
                Path = refreshPath
            });

            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Ok(new ChangePasswordResponse(true, null, null, csrfToken));
        })
        .RequireSession()
        .RequireCsrf();
    }

    /// <summary>
    private static SameSiteMode ParseSameSite(string? value, bool allowNone, bool isDevelopment, ILogger logger, string context)
    {
        var sameSiteString = string.IsNullOrWhiteSpace(value) ? "Strict" : value;
        var sameSite = SameSiteMode.Strict;
        if (sameSiteString.Equals("Lax", StringComparison.OrdinalIgnoreCase))
            sameSite = SameSiteMode.Lax;
        else if (sameSiteString.Equals("None", StringComparison.OrdinalIgnoreCase))
            sameSite = SameSiteMode.None;
        else if (!sameSiteString.Equals("Strict", StringComparison.OrdinalIgnoreCase))
            logger.LogWarning("{Context}:SameSite non valido ({SameSite}), fallback a Strict", context, sameSiteString);

        if (!isDevelopment && sameSite == SameSiteMode.None && !allowNone)
        {
            logger.LogWarning("{Context}:SameSite=None in ambiente non Development non consentito: forzato a Strict (abilita {Context}:AllowSameSiteNone per override esplicito)", context, sameSiteString);
            sameSite = SameSiteMode.Strict;
        }

        return sameSite;
    }
}


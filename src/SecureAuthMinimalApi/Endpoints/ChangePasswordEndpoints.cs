using System.Text.Json;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace SecureAuthMinimalApi.Endpoints;

public static class ChangePasswordEndpoints
{
    public static void MapChangePassword(this WebApplication app)
    {
        app.MapPost("/me/password", async (
            HttpContext ctx,
            JwtTokenService jwt,
            SessionRepository sessions,
            UserRepository users,
            RefreshTokenRepository refreshRepo,
            IConfiguration config,
            IWebHostEnvironment env,
            ILogger<ChangePasswordLoggerMarker> logger) =>
        {
            var policy = LoadPasswordPolicy(config);
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

            var policyErrors = AuthHelpers.ValidatePassword(newPassword.Trim(), policy.MinLength, policy.RequireUpper, policy.RequireLower, policy.RequireDigit, policy.RequireSymbol);
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

            var requireSecureConfig = config.GetValue<bool>("Cookie:RequireSecure");
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
            var refreshCookieName = config["RememberMe:CookieName"] ?? "refresh_token";
            var refreshPath = config["RememberMe:Path"] ?? "/refresh";
            var rememberSameSiteString = config["RememberMe:SameSite"] ?? "Strict";
            var rememberSameSite = SameSiteMode.Strict;
            if (rememberSameSiteString.Equals("Lax", StringComparison.OrdinalIgnoreCase))
                rememberSameSite = SameSiteMode.Lax;
            else if (rememberSameSiteString.Equals("None", StringComparison.OrdinalIgnoreCase))
                rememberSameSite = SameSiteMode.None;
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
        });
    }

    private static PasswordPolicySettings LoadPasswordPolicy(IConfiguration config)
    {
        var configuredMin = config.GetValue<int?>("PasswordPolicy:MinLength");
        var minPasswordLength = configuredMin is null or < 1 ? 12 : configuredMin.Value;
        var requireUpper = config.GetValue<bool?>("PasswordPolicy:RequireUpper") ?? false;
        var requireLower = config.GetValue<bool?>("PasswordPolicy:RequireLower") ?? false;
        var requireDigit = config.GetValue<bool?>("PasswordPolicy:RequireDigit") ?? false;
        var requireSymbol = config.GetValue<bool?>("PasswordPolicy:RequireSymbol") ?? false;
        return new PasswordPolicySettings(minPasswordLength, requireUpper, requireLower, requireDigit, requireSymbol);
    }

    private static byte[] RandomBytes(int len)
    {
        var b = new byte[len];
        System.Security.Cryptography.RandomNumberGenerator.Fill(b);
        return b;
    }

    private static string Base64Url(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}

public sealed class ChangePasswordLoggerMarker;

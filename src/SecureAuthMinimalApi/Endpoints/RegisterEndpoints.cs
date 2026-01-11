using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Options;
using SecureAuthMinimalApi.Services;
using SecureAuthMinimalApi.Utilities;
using SecureAuthMinimalApi.Logging;
using static SecureAuthMinimalApi.Endpoints.EndpointUtilities;

namespace SecureAuthMinimalApi.Endpoints;

public static class RegisterEndpoints
{
    /// <summary>
    /// Mappa l'endpoint di registrazione utenti applicando la policy password.
    /// </summary>
    public static void MapRegister(
        this WebApplication app,
        PasswordPolicyOptions passwordPolicy,
        UsernamePolicyOptions usernamePolicy)
    {
        app.MapPost("/register", async (HttpContext ctx, UserRepository users, ILogger<RegisterLogger> logger, IEmailService emailService) =>
        {
            var req = await ctx.Request.ReadFromJsonAsync<RegisterRequest>();
            var username = NormalizeUsername(req?.Username, usernamePolicy.Lowercase);
            var email = NormalizeEmail(req?.Email);
            var password = req?.Password ?? "";
            var givenNameInput = req?.GivenName?.Trim();
            var familyNameInput = req?.FamilyName?.Trim();
            var nameInput = req?.Name?.Trim();
            var pictureUrlInput = req?.Picture?.Trim();

            logger.LogInformation("Registrazione avviata username={Username} email={Email}", username, email);
            var inputErrors = new List<string>();
            if (string.IsNullOrWhiteSpace(username))
                inputErrors.Add("username_required");
            if (string.IsNullOrWhiteSpace(email))
                inputErrors.Add("email_required");
            else if (!email.Contains('@', StringComparison.Ordinal))
                inputErrors.Add("email_invalid");
            if (string.IsNullOrWhiteSpace(password))
                inputErrors.Add("password_required");
            if (!string.IsNullOrWhiteSpace(pictureUrlInput))
            {
                if (!Uri.TryCreate(pictureUrlInput, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
                    inputErrors.Add("picture_invalid");
            }
            if (inputErrors.Any())
            {
                logger.LogWarning("Registrazione input non valido username={Username} email={Email} errors={Errors}", username, email, string.Join(",", inputErrors));
                return Results.BadRequest(new { ok = false, error = "invalid_input", errors = inputErrors });
            }
            var safeUsername = username!;
            var safeEmail = email!;
            var givenName = string.IsNullOrWhiteSpace(givenNameInput) ? safeUsername : givenNameInput;
            var familyName = string.IsNullOrWhiteSpace(familyNameInput) ? "User" : familyNameInput;
            var fullName = string.IsNullOrWhiteSpace(nameInput) ? $"{givenName} {familyName}".Trim() : nameInput;
            var pictureUrl = string.IsNullOrWhiteSpace(pictureUrlInput) ? $"https://example.com/avatar/{safeUsername}.png" : pictureUrlInput;

            var effectiveMin = passwordPolicy.EffectiveMinLength;
            var policyErrors = AuthHelpers.ValidatePassword(password, effectiveMin, passwordPolicy.RequireUpper, passwordPolicy.RequireLower, passwordPolicy.RequireDigit, passwordPolicy.RequireSymbol);
            if (policyErrors.Any())
            {
                logger.LogWarning("Registrazione fallita: password non conforme username={Username} errors={Errors}", safeUsername, string.Join(",", policyErrors));
                return Results.BadRequest(new { ok = false, error = "password_policy_failed", errors = policyErrors });
            }
            else
            {
                logger.LogInformation("Registrazione: password conforme policy username={Username}", safeUsername);
            }

            var emailConfirmToken = Guid.NewGuid().ToString("N");
            var emailConfirmExpires = DateTime.UtcNow.AddHours(24);

            var existing = await users.GetByUsernameAsync(safeUsername, ctx.RequestAborted);
            if (existing is not null)
            {
                logger.LogWarning("Registrazione rifiutata: username esistente username={Username}", safeUsername);
                return Results.StatusCode(StatusCodes.Status409Conflict);
            }

            var existingEmail = await users.GetByEmailAsync(safeEmail, ctx.RequestAborted);
            if (existingEmail is not null)
            {
                logger.LogWarning("Registrazione rifiutata: email esistente email={Email}", safeEmail);
                return Results.StatusCode(StatusCodes.Status409Conflict);
            }

            var user = new User
            {
                Id = Guid.NewGuid().ToString("N"),
                Username = safeUsername,
                PasswordHash = PasswordHasher.Hash(password),
                CreatedAtUtc = DateTime.UtcNow.ToString("O"),
                IsLocked = false,
                DeletedAtUtc = null,
                Name = string.IsNullOrWhiteSpace(fullName) ? null : fullName,
                GivenName = givenName!,
                FamilyName = familyName!,
                Email = req!.Email!,
                EmailNormalized = safeEmail,
                EmailConfirmed = false,
                EmailConfirmToken = emailConfirmToken,
                EmailConfirmExpiresUtc = emailConfirmExpires.ToString("O"),
                PictureUrl = pictureUrl
            };

            await users.CreateAsync(user, ctx.RequestAborted);
            logger.LogInformation("Registrazione OK username={Username} userId={UserId} created={Created} emailToken={EmailToken} exp={EmailExp}", user.Username, user.Id, user.CreatedAtUtc, emailConfirmToken, emailConfirmExpires.ToString("O"));

            if (!string.IsNullOrWhiteSpace(user.Email))
            {
                try
                {
                    await emailService.SendEmailConfirmationAsync(user.Email!, emailConfirmToken, emailConfirmExpires.ToString("O"));
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Errore invio email conferma per registrazione userId={UserId}", user.Id);
                }
            }

            return Results.Created($"/users/{user.Id}", new { ok = true, userId = user.Id, email = user.Email, emailConfirmToken, emailConfirmExpiresUtc = emailConfirmExpires.ToString("O") });
        });
    }
}

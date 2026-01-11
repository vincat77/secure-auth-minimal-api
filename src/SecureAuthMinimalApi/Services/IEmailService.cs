namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Contratto minimo per l'invio di email (stub per reset password).
/// </summary>
public interface IEmailService
{
    Task SendPasswordResetEmailAsync(string toEmail, string resetToken, string expiresAtUtc);
    Task SendEmailConfirmationAsync(string toEmail, string confirmToken, string expiresAtUtc);
}

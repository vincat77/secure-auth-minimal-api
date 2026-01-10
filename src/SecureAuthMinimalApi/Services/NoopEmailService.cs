using Microsoft.Extensions.Logging;

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Implementazione stub che logga l'invio email (solo dev/test).
/// </summary>
public sealed class NoopEmailService : IEmailService
{
    private readonly ILogger<NoopEmailService> _logger;

    public NoopEmailService(ILogger<NoopEmailService> logger)
    {
        _logger = logger;
    }

    public Task SendPasswordResetEmailAsync(string toEmail, string resetToken, string expiresAtUtc)
    {
        _logger.LogInformation("Invio email reset password a {Email} token={Token} exp={Exp}", toEmail, resetToken, expiresAtUtc);
        return Task.CompletedTask;
    }

    public Task SendEmailConfirmationAsync(string toEmail, string confirmToken, string expiresAtUtc)
    {
        _logger.LogInformation("Invio email conferma a {Email} token={Token} exp={Exp}", toEmail, confirmToken, expiresAtUtc);
        return Task.CompletedTask;
    }
}

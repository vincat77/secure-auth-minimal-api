namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Configurazione per reset password.
/// </summary>
public sealed class PasswordResetConfig
{
    public int ExpirationMinutes { get; set; } = 30;
    public bool RequireConfirmed { get; set; } = true;
    public bool IncludeTokenInResponseForTesting { get; set; } = false;
    public int RetentionDays { get; set; } = 7;
}

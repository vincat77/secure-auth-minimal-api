namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Modello per i token di reset password.
/// </summary>
public sealed class PasswordReset
{
    public string Id { get; init; } = default!;
    public string UserId { get; init; } = default!;
    public string TokenHash { get; init; } = default!;
    public string ExpiresAtUtc { get; init; } = default!;
    public string? UsedAtUtc { get; init; }
    public string CreatedAtUtc { get; init; } = default!;
    public string? ClientIp { get; init; }
    public string? UserAgent { get; init; }
}

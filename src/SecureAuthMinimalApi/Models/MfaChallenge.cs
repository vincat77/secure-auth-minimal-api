namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Challenge MFA generato dopo la verifica password per utenti con TOTP.
/// </summary>
public sealed class MfaChallenge
{
    public required string Id { get; init; }
    public required string UserId { get; init; }
    public required string CreatedAtUtc { get; init; }
    public required string ExpiresAtUtc { get; init; }
    public string? UsedAtUtc { get; init; }
    public string? UserAgent { get; init; }
    public string? ClientIp { get; init; }
    public int AttemptCount { get; init; }
}

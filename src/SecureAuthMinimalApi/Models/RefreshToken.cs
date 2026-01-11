namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Token di refresh persistente per Remember Me / rotazione sessione.
/// </summary>
public sealed class RefreshToken
{
    public required string Id { get; init; }
    public required string UserId { get; init; }
    public string? SessionId { get; init; }
    public required string Token { get; init; }
    public required string CreatedAtUtc { get; init; }
    public required string ExpiresAtUtc { get; init; }
    public string? RevokedAtUtc { get; init; }
    public string? UserAgent { get; init; }
    public string? ClientIp { get; init; }
    public string? DeviceId { get; init; }
    public string? DeviceLabel { get; init; }
    public string? RotationParentId { get; init; }
    public string? RotationReason { get; init; }
    public string? TokenHash { get; init; }
    public string? RefreshCsrfHash { get; init; }
}

namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Evento di audit login (success/fail/lockout).
/// </summary>
public sealed class LoginAudit
{
    public required string Id { get; init; }
    public required string Username { get; init; }
    public required string Outcome { get; init; }          // success | user_not_found | invalid_credentials | locked
    public required string TimestampUtc { get; init; }
    public string? ClientIp { get; init; }
    public string? UserAgent { get; init; }
    public string? Detail { get; init; }
}

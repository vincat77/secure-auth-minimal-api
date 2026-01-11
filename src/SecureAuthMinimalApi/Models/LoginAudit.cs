namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Evento di audit login (success/fail/lockout).
/// </summary>
public sealed class LoginAudit
{
    /// <summary>Id audit (PK).</summary>
    public required string Id { get; init; }
    /// <summary>Username interessato.</summary>
    public required string Username { get; init; }
    /// <summary>Esito: success | user_not_found | invalid_credentials | locked.</summary>
    public required string Outcome { get; init; }
    /// <summary>Timestamp UTC (ISO 8601).</summary>
    public required string TimestampUtc { get; init; }
    /// <summary>IP client.</summary>
    public string? ClientIp { get; init; }
    /// <summary>User-Agent client.</summary>
    public string? UserAgent { get; init; }
    /// <summary>Dettagli aggiuntivi.</summary>
    public string? Detail { get; init; }
}

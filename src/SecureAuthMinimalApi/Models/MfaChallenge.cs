namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Challenge MFA generato dopo la verifica password per utenti con TOTP.
/// </summary>
public sealed class MfaChallenge
{
    /// <summary>Id della challenge (PK).</summary>
    public required string Id { get; init; }
    /// <summary>UserId associato alla challenge.</summary>
    public required string UserId { get; init; }
    /// <summary>Data creazione (ISO 8601 UTC).</summary>
    public required string CreatedAtUtc { get; init; }
    /// <summary>Data scadenza (ISO 8601 UTC).</summary>
    public required string ExpiresAtUtc { get; init; }
    /// <summary>Data utilizzo (ISO 8601 UTC) o null se non usata.</summary>
    public string? UsedAtUtc { get; init; }
    /// <summary>User-Agent registrato al momento della creazione.</summary>
    public string? UserAgent { get; init; }
    /// <summary>IP registrato al momento della creazione.</summary>
    public string? ClientIp { get; init; }
    /// <summary>Numero di tentativi TOTP effettuati.</summary>
    public int AttemptCount { get; init; }
}

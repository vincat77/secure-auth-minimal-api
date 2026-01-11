namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Modello per i token di reset password.
/// </summary>
public sealed class PasswordReset
{
    /// <summary>Id reset token (PK).</summary>
    public string Id { get; init; } = default!;
    /// <summary>UserId associato.</summary>
    public string UserId { get; init; } = default!;
    /// <summary>Hash del token (persistito).</summary>
    public string TokenHash { get; init; } = default!;
    /// <summary>Scadenza token (ISO 8601 UTC).</summary>
    public string ExpiresAtUtc { get; init; } = default!;
    /// <summary>Data di utilizzo (ISO 8601 UTC) o null.</summary>
    public string? UsedAtUtc { get; init; }
    /// <summary>Data creazione (ISO 8601 UTC).</summary>
    public string CreatedAtUtc { get; init; } = default!;
    /// <summary>IP del client che ha richiesto il reset.</summary>
    public string? ClientIp { get; init; }
    /// <summary>User-Agent del client che ha richiesto il reset.</summary>
    public string? UserAgent { get; init; }
}

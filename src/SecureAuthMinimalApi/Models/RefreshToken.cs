namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Token di refresh persistente per Remember Me / rotazione sessione.
/// </summary>
public sealed class RefreshToken
{
    /// <summary>Id refresh token (PK).</summary>
    public required string Id { get; init; }
    /// <summary>UserId proprietario.</summary>
    public required string UserId { get; init; }
    /// <summary>SessionId associata (può essere null).</summary>
    public string? SessionId { get; init; }
    /// <summary>Valore in chiaro (solo in transito, mai salvato hashato dopo Create).</summary>
    public required string Token { get; init; }
    /// <summary>Data creazione (ISO 8601 UTC).</summary>
    public required string CreatedAtUtc { get; init; }
    /// <summary>Data scadenza (ISO 8601 UTC).</summary>
    public required string ExpiresAtUtc { get; init; }
    /// <summary>Data revoca (ISO 8601 UTC) o null.</summary>
    public string? RevokedAtUtc { get; init; }
    /// <summary>User-Agent registrato al momento dell'emissione.</summary>
    public string? UserAgent { get; init; }
    /// <summary>IP registrato al momento dell'emissione.</summary>
    public string? ClientIp { get; init; }
    /// <summary>DeviceId associato (cookie device).</summary>
    public string? DeviceId { get; init; }
    /// <summary>Etichetta dispositivo (se presente).</summary>
    public string? DeviceLabel { get; init; }
    /// <summary>Id del refresh "genitore" in caso di rotazione.</summary>
    public string? RotationParentId { get; init; }
    /// <summary>Motivo della rotazione/revoca.</summary>
    public string? RotationReason { get; init; }
    /// <summary>Hash HMAC del token (persistito).</summary>
    public string? TokenHash { get; init; }
    /// <summary>Hash del refresh CSRF token (persistito).</summary>
    public string? RefreshCsrfHash { get; init; }
}

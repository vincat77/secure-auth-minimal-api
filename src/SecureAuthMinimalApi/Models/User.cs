namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Modello utente persistito (password hashata, username univoco).
/// </summary>
public sealed class User
{
    /// <summary>Id utente (PK).</summary>
    public required string Id { get; init; }
    /// <summary>Username univoco (normalizzato secondo policy).</summary>
    public required string Username { get; init; }
    /// <summary>Hash della password (BCrypt/altro).</summary>
    public required string PasswordHash { get; init; }
    /// <summary>Data creazione (ISO 8601 UTC).</summary>
    public required string CreatedAtUtc { get; init; }
    /// <summary>Flag account bloccato.</summary>
    public bool IsLocked { get; init; }
    /// <summary>Soft delete timestamp (UTC) se presente.</summary>
    public string? DeletedAtUtc { get; init; }
    /// <summary>Segreto TOTP cifrato (se MFA abilitato).</summary>
    public string? TotpSecret { get; init; }
    /// <summary>Nome completo opzionale.</summary>
    public string? Name { get; init; }
    /// <summary>Nome proprio.</summary>
    public string? GivenName { get; init; }
    /// <summary>Cognome.</summary>
    public string? FamilyName { get; init; }
    /// <summary>Email (raw).</summary>
    public string? Email { get; init; }
    /// <summary>Email normalizzata (lowercase).</summary>
    public string? EmailNormalized { get; init; }
    /// <summary>Flag email confermata.</summary>
    public bool EmailConfirmed { get; init; }
    /// <summary>Token conferma email.</summary>
    public string? EmailConfirmToken { get; init; }
    /// <summary>Scadenza token conferma email (UTC ISO).</summary>
    public string? EmailConfirmExpiresUtc { get; init; }
    /// <summary>URL immagine profilo.</summary>
    public string? PictureUrl { get; init; }
}

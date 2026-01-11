namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Rappresenta una sessione server-side persistita in SQLite.
/// Contiene solo dati lato server (nessun dato utente nel JWT) e token CSRF sincronizzato.
/// </summary>
public sealed class UserSession
{
    /// <summary>Identificativo sessione (sub nel JWT).</summary>
    public required string SessionId { get; init; }
    /// <summary>Id utente proprietario della sessione.</summary>
    public required string UserId { get; init; }
    /// <summary>Data creazione sessione (ISO 8601 UTC).</summary>
    public required string CreatedAtUtc { get; init; }
    /// <summary>Data scadenza sessione (ISO 8601 UTC).</summary>
    public required string ExpiresAtUtc { get; init; }
    /// <summary>Data revoca (ISO 8601 UTC) o null se attiva.</summary>
    public string? RevokedAtUtc { get; init; }
    /// <summary>Dati utente serializzati lato server (non nel JWT).</summary>
    public required string UserDataJson { get; init; }
    /// <summary>Token CSRF sincronizzato con la sessione.</summary>
    public required string CsrfToken { get; init; }
    /// <summary>Ultimo accesso (ISO 8601 UTC) per idle timeout.</summary>
    public required string LastSeenUtc { get; init; }
}

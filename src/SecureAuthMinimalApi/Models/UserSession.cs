namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Rappresenta una sessione server-side persistita in SQLite.
/// Contiene solo dati lato server (nessun dato utente nel JWT) e token CSRF sincronizzato.
/// </summary>
public sealed class UserSession
{
    public required string SessionId { get; init; }           // sub nel JWT (reference token)
    public required string UserId { get; init; }              // identità server-side
    public required string CreatedAtUtc { get; init; }        // ISO 8601 (DateTime.UtcNow.ToString("O"))
    public required string ExpiresAtUtc { get; init; }        // ISO 8601
    public string? RevokedAtUtc { get; init; }                // ISO 8601 o null
    public required string UserDataJson { get; init; }        // dati solo server-side (mai nel JWT)
    public required string CsrfToken { get; init; }           // token CSRF sincronizzato, solo DB
    public required string LastSeenUtc { get; init; }         // ultimo accesso, per idle timeout
}

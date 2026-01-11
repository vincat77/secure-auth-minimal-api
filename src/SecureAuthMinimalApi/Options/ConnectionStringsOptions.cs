namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Opzioni per le connection string dell'applicazione.
/// </summary>
public sealed class ConnectionStringsOptions
{
    /// <summary>
    /// Stringa di connessione SQLite (ConnectionStrings:Sqlite).
    /// </summary>
    public string? Sqlite { get; set; }
}

using SecureAuthMinimalApi.Data;

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Estensioni per la configurazione e l'avvio dell'applicazione.
/// </summary>
public static class ApplicationExtensions
{
    /// <summary>
    /// Inizializza il database SQLite (se non saltato per test) e logga l'azione.
    /// Rispetta il flag Tests:SkipDbInit per gli scenari di integrazione.
    /// </summary>
    public static void EnsureDatabaseInitialized(this WebApplication app, ILogger logger)
    {
        var skipDbInit = app.Configuration.GetValue<bool?>("Tests:SkipDbInit") ?? false;
        if (skipDbInit)
        {
            logger.LogWarning("Avvio con Tests:SkipDbInit=true: saltata inizializzazione DB (solo per test)");
            return;
        }

        DbInitializer.EnsureCreated(app.Configuration, app.Environment.IsDevelopment(), logger);
    }
}

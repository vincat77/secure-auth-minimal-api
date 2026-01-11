namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Opzioni di configurazione per il cleanup periodico dei record scaduti.
/// </summary>
public sealed class CleanupOptions
{
    /// <summary>Abilita/disabilita il job di cleanup.</summary>
    public bool Enabled { get; set; } = true;
    /// <summary>Intervallo tra run (secondi).</summary>
    public int IntervalSeconds { get; set; } = 300;
    /// <summary>Numero massimo di record per batch.</summary>
    public int BatchSize { get; set; } = 200;
    /// <summary>Limite batch per run (opzionale).</summary>
    public int? MaxIterationsPerRun { get; set; }
    /// <summary>Retention giorni per password reset (se supportato).</summary>
    public int? PasswordResetRetentionDays { get; set; }
}

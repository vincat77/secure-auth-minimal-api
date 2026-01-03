namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Opzioni di configurazione per il cleanup periodico dei record scaduti.
/// </summary>
public sealed class CleanupOptions
{
    public bool Enabled { get; set; } = true;
    public int IntervalSeconds { get; set; } = 300;
    public int BatchSize { get; set; } = 200;
    public int? MaxIterationsPerRun { get; set; }
}

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Controlla lo stato di pausa dell'applicazione in modo thread-safe.
/// </summary>
public sealed class PauseController
{
    private int _flag;

    /// <summary>
    /// Stato corrente: true se l'applicazione è in pausa.
    /// </summary>
    public bool IsPaused => Volatile.Read(ref _flag) == 1;

    /// <summary>
    /// Inverte lo stato di pausa e ritorna true se ora è in pausa.
    /// </summary>
    public bool Toggle()
    {
        var newValue = IsPaused ? 0 : 1;
        var previous = Interlocked.Exchange(ref _flag, newValue);
        return previous == 0;
    }
}

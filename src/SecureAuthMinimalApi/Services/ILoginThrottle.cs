namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Interfaccia per rate limiting/login lockout leggero.
/// </summary>
public interface ILoginThrottle
{
    /// <summary>
    /// Verifica se lo username è ancora lockato per troppi tentativi.
    /// </summary>
    Task<bool> IsLockedAsync(string username, CancellationToken ct);

    /// <summary>
    /// Registra un fallimento incrementando contatore e applicando lock se necessario.
    /// </summary>
    Task RegisterFailureAsync(string username, CancellationToken ct);

    /// <summary>
    /// Resetta lo stato di throttle dopo un login riuscito.
    /// </summary>
    Task RegisterSuccessAsync(string username, CancellationToken ct);
}

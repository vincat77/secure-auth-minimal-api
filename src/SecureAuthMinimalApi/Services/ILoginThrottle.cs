namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Interfaccia per rate limiting/login lockout leggero.
/// </summary>
public interface ILoginThrottle
{
    Task<bool> IsLockedAsync(string username, CancellationToken ct);
    Task RegisterFailureAsync(string username, CancellationToken ct);
    Task RegisterSuccessAsync(string username, CancellationToken ct);
}

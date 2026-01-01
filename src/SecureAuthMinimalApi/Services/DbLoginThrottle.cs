using SecureAuthMinimalApi.Data;
using Microsoft.Extensions.Configuration;

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Implementazione di ILoginThrottle che persiste lo stato in SQLite.
/// </summary>
public sealed class DbLoginThrottle : ILoginThrottle
{
    private readonly LoginThrottleRepository _repo;
    private readonly int _maxFailures;
    private readonly TimeSpan _lockDuration;

    public DbLoginThrottle(LoginThrottleRepository repo, IConfiguration config)
    {
        _repo = repo;
        _maxFailures = config.GetValue<int?>("LoginThrottle:MaxFailures") ?? 5;
        var lockMinutes = config.GetValue<int?>("LoginThrottle:LockMinutes") ?? 5;
        if (_maxFailures <= 0) _maxFailures = 5;
        if (lockMinutes <= 0) lockMinutes = 5;
        _lockDuration = TimeSpan.FromMinutes(lockMinutes);
    }

    public async Task<bool> IsLockedAsync(string username, CancellationToken ct)
    {
        var state = await _repo.GetAsync(username, ct);
        if (state.LockedUntilUtc > DateTimeOffset.UtcNow)
            return true;

        return false;
    }

    public async Task RegisterFailureAsync(string username, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var state = await _repo.GetAsync(username, ct);

        // reset contatore se lock scaduto
        if (state.LockedUntilUtc <= now && state.Failures >= _maxFailures)
            state = new ThrottleState(username, 0, DateTimeOffset.MinValue);

        var failures = state.Failures + 1;
        var lockedUntil = state.LockedUntilUtc;
        if (failures >= _maxFailures)
            lockedUntil = now.Add(_lockDuration);

        var newState = new ThrottleState(username, failures, lockedUntil);
        await _repo.SaveAsync(newState, ct);
    }

    public async Task RegisterSuccessAsync(string username, CancellationToken ct)
    {
        await _repo.ResetAsync(username, ct);
    }
}

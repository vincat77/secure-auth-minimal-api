using System.Collections.Concurrent;

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Rate limiter in-memory per l'endpoint /login (scoped all'applicazione).
/// </summary>
public sealed class LoginRateLimiter
{
    private readonly ConcurrentDictionary<string, ConcurrentQueue<DateTime>> _store = new();

    public bool ShouldThrottle(string key, int maxRequests, TimeSpan window)
    {
        var now = DateTime.UtcNow;
        var queue = _store.GetOrAdd(key, _ => new ConcurrentQueue<DateTime>());
        queue.Enqueue(now);

        while (queue.TryPeek(out var ts) && ts < now - window)
        {
            queue.TryDequeue(out _);
        }

        return queue.Count > maxRequests;
    }
}

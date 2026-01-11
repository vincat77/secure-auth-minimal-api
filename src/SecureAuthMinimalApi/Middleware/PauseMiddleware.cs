using Microsoft.Extensions.Logging;
using System.Threading;

namespace SecureAuthMinimalApi.Middleware;

/// <summary>
/// Blocca le richieste quando l'applicazione è in pausa (flag volatile esterno).
/// </summary>
public sealed class PauseMiddleware
{
    private readonly RequestDelegate _next;
    private readonly Func<bool> _isPaused;
    private readonly ILogger<PauseMiddleware> _logger;

    public PauseMiddleware(RequestDelegate next, Func<bool> isPaused, ILogger<PauseMiddleware> logger)
    {
        _next = next;
        _isPaused = isPaused;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (_isPaused())
        {
            _logger.LogWarning("Richiesta respinta: applicazione in pausa {Method} {Path}", context.Request.Method, context.Request.Path);
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await context.Response.WriteAsJsonAsync(new { ok = false, error = "paused" });
            return;
        }

        await _next(context);
    }
}

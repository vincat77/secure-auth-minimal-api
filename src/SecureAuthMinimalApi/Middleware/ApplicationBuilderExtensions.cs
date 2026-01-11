namespace SecureAuthMinimalApi.Middleware;

/// <summary>
/// Estensioni per registrare i middleware personalizzati.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Aggiunge il middleware di logging + handling UnauthorizedAccessException.
    /// </summary>
    public static IApplicationBuilder UseRequestLoggingWithUnauthorizedHandling(this IApplicationBuilder app)
    {
        return app.UseMiddleware<RequestLoggingMiddleware>();
    }

    /// <summary>
    /// Aggiunge il middleware di headers di hardening.
    /// </summary>
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
    {
        return app.UseMiddleware<SecurityHeadersMiddleware>();
    }

    /// <summary>
    /// Aggiunge il middleware di pausa: se il delegato restituisce true, risponde 503.
    /// </summary>
    public static IApplicationBuilder UsePauseMiddleware(this IApplicationBuilder app, Func<bool> isPaused)
    {
        return app.UseMiddleware<PauseMiddleware>(isPaused);
    }
}

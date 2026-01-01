using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Services;

namespace SecureAuthMinimalApi.Middleware;

/// <summary>
/// Estrae il JWT dal cookie, valida firma/iss/aud/exp e carica la sessione dal DB, verificando revoca/scadenza server-side.
/// Non genera eccezioni su token invalidi (lascia endpoint gestire 401).
/// </summary>
public sealed class CookieJwtAuthMiddleware : IMiddleware
{
    private readonly IServiceProvider _provider;
    private readonly SessionRepository _sessions;
    private readonly JwtSecurityTokenHandler _handler = new() { MapInboundClaims = false };
    private TokenValidationParameters? _tvp;
    private JwtTokenService? _jwt;
    private readonly ILogger<CookieJwtAuthMiddleware> _logger;

    public CookieJwtAuthMiddleware(IServiceProvider provider, SessionRepository sessions, ILogger<CookieJwtAuthMiddleware> logger)
    {
        _provider = provider;
        _sessions = sessions;
        _logger = logger;
    }

    /// <summary>
    /// Valida il token se presente e popola HttpContext.Items["session"].
    /// </summary>
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        if (_jwt is null)
        {
            try
            {
                _jwt = _provider.GetRequiredService<JwtTokenService>();
                _tvp = _jwt.GetValidationParameters();
            }
            catch (Exception ex)
            {
                // Config JWT non valida: log e prosegui senza auth (evita 500 su /ready)
                _logger.LogWarning(ex, "Auth KO configurazione JWT non valida");
            }
        }

        var tvp = _tvp;
        // IMPORTANT: JWT errors must be ignored (no exception surfacing).
        // Endpoints enforce 401 when they require auth.
        if (tvp is not null && context.Request.Cookies.TryGetValue("access_token", out var token) && !string.IsNullOrWhiteSpace(token))
        {
            try
            {
                var principal = _handler.ValidateToken(token, tvp, out var validatedToken);

                if (validatedToken is JwtSecurityToken jwtToken &&
                    string.Equals(jwtToken.Header.Alg, SecurityAlgorithms.HmacSha256, StringComparison.OrdinalIgnoreCase))
                {
                    var exp = jwtToken.ValidTo.ToUniversalTime();
                    var iss = jwtToken.Issuer;
                    var aud = string.Join(",", jwtToken.Audiences);
                    var sessionId = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                    if (!string.IsNullOrWhiteSpace(sessionId))
                    {
                        var session = await _sessions.GetByIdAsync(sessionId, context.RequestAborted);
                        if (session is not null)
                        {
                            // immediate revocation check (server-side source of truth)
                            if (session.RevokedAtUtc is null)
                            {
                                var expiresUtc = DateTime.Parse(session.ExpiresAtUtc).ToUniversalTime();
                                if (expiresUtc > DateTime.UtcNow)
                                {
                                    context.Items["session"] = session;
                                    context.User = principal;
                                    _logger.LogInformation("Auth OK sessione attiva sessionId={SessionId} userId={UserId} exp={Exp} jwtExp={JwtExp} iss={Iss} aud={Aud} {Method} {Path}", session.SessionId, session.UserId, session.ExpiresAtUtc, exp.ToString("O"), iss, aud, context.Request.Method, context.Request.Path);
                                }
                                else
                                {
                                    _logger.LogInformation("Auth KO sessione scaduta sessionId={SessionId} userId={UserId} exp={Exp} {Method} {Path}", session.SessionId, session.UserId, session.ExpiresAtUtc, context.Request.Method, context.Request.Path);
                                }
                            }
                            else
                            {
                                _logger.LogInformation("Auth KO sessione revocata sessionId={SessionId} userId={UserId} revokedAt={Revoked} {Method} {Path}", session.SessionId, session.UserId, session.RevokedAtUtc, context.Request.Method, context.Request.Path);
                            }
                        }
                        else
                        {
                            _logger.LogWarning("Auth KO sessione non trovata sessionId={SessionId} {Method} {Path}", sessionId, context.Request.Method, context.Request.Path);
                        }
                    }
                }
            }
            catch (SecurityTokenException)
            {
                // ignore invalid token
                _logger.LogWarning("Auth KO token non valido {Method} {Path}", context.Request.Method, context.Request.Path);
            }
            catch (ArgumentException)
            {
                // ignore malformed token
                _logger.LogWarning("Auth KO token malformato {Method} {Path}", context.Request.Method, context.Request.Path);
            }
        }

        await next(context);
    }
}

public static class CookieJwtAuthExtensions
{
    public static IApplicationBuilder UseCookieJwtAuth(this IApplicationBuilder app)
        => app.UseMiddleware<CookieJwtAuthMiddleware>();
}

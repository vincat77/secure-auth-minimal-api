using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureAuthMinimalApi.Options;

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Gestisce creazione e validazione di access token JWT HMAC-SHA256 con payload minimale.
/// </summary>
public sealed class JwtTokenService
{
    private readonly string _issuer;
    private readonly string _audience;
    private readonly byte[] _keyBytes;
    private readonly int _accessTokenMinutes;

    /// <summary>
    /// Inizializza issuer/audience/chiave da configurazione e valida segreti.
    /// </summary>
    public JwtTokenService(IOptions<JwtOptions> jwtOptions)
    {
        var options = jwtOptions.Value;
        _issuer = string.IsNullOrWhiteSpace(options.Issuer)
            ? throw new InvalidOperationException("Missing Jwt:Issuer in appsettings.json")
            : options.Issuer;
        _audience = string.IsNullOrWhiteSpace(options.Audience)
            ? throw new InvalidOperationException("Missing Jwt:Audience in appsettings.json")
            : options.Audience;

        var secret = options.SecretKey;
        if (string.IsNullOrWhiteSpace(secret))
            throw new InvalidOperationException("Missing Jwt:SecretKey in appsettings.json");
        if (secret.Trim().Length < 32)
            throw new InvalidOperationException("Jwt:SecretKey must be at least 32 characters");

        _keyBytes = Encoding.UTF8.GetBytes(secret);
        _accessTokenMinutes = options.AccessTokenMinutes;
        if (_accessTokenMinutes <= 0)
            throw new InvalidOperationException("Jwt:AccessTokenMinutes must be > 0");
    }

    /// <summary>
    /// Genera un JWT di accesso contenente solo sub/jti/iat/exp/iss/aud.
    /// </summary>
    public (string Token, DateTime ExpiresUtc) CreateAccessToken(string sessionId)
    {
        // JWT is a reference token: payload must NOT contain user data.
        // Payload ONLY: sub (sessionId), jti, iat, exp, iss, aud.
        var nowUtc = DateTime.UtcNow;
        var expiresUtc = nowUtc.AddMinutes(_accessTokenMinutes);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, sessionId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            // iat MUST be numeric date (seconds since epoch). Using Integer64.
            new(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(nowUtc).ToString(), ClaimValueTypes.Integer64),
        };

        var creds = new SigningCredentials(new SymmetricSecurityKey(_keyBytes), SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            notBefore: nowUtc,
            expires: expiresUtc,
            signingCredentials: creds);

        var handler = new JwtSecurityTokenHandler();
        return (handler.WriteToken(token), expiresUtc);
    }

    /// <summary>
    /// Parametri di validazione consistenti per middleware e test.
    /// </summary>
    public TokenValidationParameters GetValidationParameters()
        => new()
        {
            ValidateIssuer = true,
            ValidIssuer = _issuer,
            ValidateAudience = true,
            ValidAudience = _audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(_keyBytes),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30) // small skew; keep tight
        };
}

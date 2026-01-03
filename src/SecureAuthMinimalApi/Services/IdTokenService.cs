using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Genera id_token JWT firmati (RSA preferito, fallback HMAC in dev).
/// </summary>
public sealed class IdTokenService
{
    private readonly string _issuer;
    private readonly string _audience;
    private readonly SigningCredentials _creds;
    private readonly TokenValidationParameters _validation;

    public IdTokenService(IConfiguration config)
    {
        _issuer = config["IdToken:Issuer"] ?? config["Jwt:Issuer"] ?? throw new InvalidOperationException("Missing IdToken:Issuer");
        _audience = config["IdToken:Audience"] ?? config["Jwt:Audience"] ?? throw new InvalidOperationException("Missing IdToken:Audience");
        // Email e claim profilo sempre inclusi se disponibili (nessun scope).

        var signingKeyPath = config["IdToken:SigningKeyPath"];
        if (!string.IsNullOrWhiteSpace(signingKeyPath) && File.Exists(signingKeyPath))
        {
            var keyText = File.ReadAllText(signingKeyPath);
            _creds = CreateRsaCredentials(keyText);
        }
        else
        {
            // Fallback HMAC (solo dev). Usa chiave separata se presente, altrimenti riusa Jwt:SecretKey.
            var secret = config["IdToken:Secret"] ?? config["Jwt:SecretKey"]
                ?? throw new InvalidOperationException("Missing IdToken:SigningKeyPath and IdToken:Secret/Jwt:SecretKey");
            if (secret.Length < 32)
                throw new InvalidOperationException("IdToken secret must be at least 32 characters");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            _creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        }

        _validation = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _issuer,
            ValidateAudience = true,
            ValidAudience = _audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _creds.Key,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    }

    public (string Token, DateTime ExpiresUtc) CreateIdToken(
        string userId,
        string username,
        string? email,
        bool mfaConfirmed,
        string? nonce = null,
        int minutes = 30,
        string? name = null,
        string? givenName = null,
        string? familyName = null,
        string? pictureUrl = null)
    {
        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(minutes);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64),
            new("auth_time", EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64),
            new("amr", mfaConfirmed ? "mfa" : "pwd")
        };

        if (!string.IsNullOrWhiteSpace(nonce))
            claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));

        if (!string.IsNullOrWhiteSpace(email))
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, email));

        if (!string.IsNullOrWhiteSpace(name))
            claims.Add(new Claim(JwtRegisteredClaimNames.Name, name));

        if (!string.IsNullOrWhiteSpace(givenName))
            claims.Add(new Claim("given_name", givenName));

        if (!string.IsNullOrWhiteSpace(familyName))
            claims.Add(new Claim("family_name", familyName));

        claims.Add(new Claim("preferred_username", username));

        if (!string.IsNullOrWhiteSpace(pictureUrl))
            claims.Add(new Claim("picture", pictureUrl));

        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            notBefore: now,
            expires: expires,
            signingCredentials: _creds);

        var handler = new JwtSecurityTokenHandler();
        return (handler.WriteToken(token), expires);
    }

    public TokenValidationParameters GetValidationParameters() => _validation;

    private static SigningCredentials CreateRsaCredentials(string keyText)
    {
        try
        {
            // Try PEM first
            var rsa = RSA.Create();
            rsa.ImportFromPem(keyText.AsSpan());
            var rsaKey = new RsaSecurityKey(rsa);
            return new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);
        }
        catch
        {
            // Try XML
            var rsa = RSA.Create();
            rsa.FromXmlString(keyText);
            var rsaKey = new RsaSecurityKey(rsa);
            return new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);
        }
    }
}

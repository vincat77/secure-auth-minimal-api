using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Calcola l'HMAC dei refresh token per evitare storage in chiaro.
/// </summary>
public sealed class RefreshTokenHasher
{
    private readonly byte[] _key;

    public RefreshTokenHasher(IConfiguration config)
    {
        var key = config["Refresh:HmacKey"] ?? config["Jwt:SecretKey"];
        if (string.IsNullOrWhiteSpace(key) || key.Length < 32)
            throw new InvalidOperationException("Refresh:HmacKey (o Jwt:SecretKey) deve essere presente e di almeno 32 caratteri");
        _key = Encoding.UTF8.GetBytes(key);
    }

    /// <summary>
    /// Calcola l'HMAC-SHA256 del token in ingresso.
    /// </summary>
    public string ComputeHash(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        var tokenBytes = Encoding.UTF8.GetBytes(token);
        using var hmac = new HMACSHA256(_key);
        var hash = hmac.ComputeHash(tokenBytes);
        return Convert.ToBase64String(hash);
    }
}

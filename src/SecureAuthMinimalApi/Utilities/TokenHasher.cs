using System.Security.Cryptography;
using System.Text;

namespace SecureAuthMinimalApi.Utilities;

/// <summary>
/// Helper per hashing HMAC dei token (base64url).
/// </summary>
public static class TokenHasher
{
    public static string HmacSha256Base64Url(string pepper, string token)
    {
        if (string.IsNullOrWhiteSpace(pepper))
            throw new InvalidOperationException("Token pepper mancante");
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentException("Token mancante", nameof(token));

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(pepper));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(token));
        return Base64UrlEncode(hash);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

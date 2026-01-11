using System.Security.Cryptography;
using System.Text;

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Utility di sicurezza comuni (confronti constant-time, hashing, ecc.).
/// </summary>
public static class SecurityUtils
{
    /// <summary>
    /// Confronto in tempo costante tra due stringhe (UTF8).
    /// </summary>
    public static bool FixedTimeEquals(string a, string b)
    {
        var aBytes = Encoding.UTF8.GetBytes(a ?? string.Empty);
        var bBytes = Encoding.UTF8.GetBytes(b ?? string.Empty);
        if (aBytes.Length != bBytes.Length)
            return false;
        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }

    /// <summary>
    /// Calcola l'hash SHA256 in hex lower-case del token.
    /// </summary>
    public static string HashToken(string token)
    {
        using var sha = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(token ?? string.Empty);
        var hash = sha.ComputeHash(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

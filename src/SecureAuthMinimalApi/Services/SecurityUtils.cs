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
}

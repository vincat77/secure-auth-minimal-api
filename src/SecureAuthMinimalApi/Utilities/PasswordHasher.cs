using System.Security.Cryptography;

namespace SecureAuthMinimalApi.Utilities;

/// <summary>
/// Hashing password con salt per registrazione/login/reset.
/// </summary>
public static class PasswordHasher
{
    /// <summary>
    /// Genera hash salted (SHA256) della password.
    /// </summary>
    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var bytes = System.Text.Encoding.UTF8.GetBytes(password ?? string.Empty);
        var salted = salt.Concat(bytes).ToArray();
        var hash = SHA256.HashData(salted);
        return $"{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
    }

    /// <summary>
    /// Verifica hash salted (SHA256) della password.
    /// </summary>
    public static bool Verify(string password, string hash)
    {
        if (string.IsNullOrWhiteSpace(hash) || !hash.Contains('.'))
            return false;

        var parts = hash.Split('.', 2);
        var salt = Convert.FromBase64String(parts[0]);
        var expected = Convert.FromBase64String(parts[1]);
        var bytes = System.Text.Encoding.UTF8.GetBytes(password ?? string.Empty);
        var salted = salt.Concat(bytes).ToArray();
        var actual = SHA256.HashData(salted);
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}

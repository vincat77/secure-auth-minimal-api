using BCrypt.Net;

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Wrappa BCrypt per hash/verify password (parametri predefiniti).
/// </summary>
/// <summary>
/// Wrappa BCrypt per hash/verify password (parametri predefiniti).
/// </summary>
public static class PasswordHasher
{
    /// <summary>
    /// Hasha la password usando BCrypt work factor 12.
    /// </summary>
    public static string Hash(string password)
        => BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);

    /// <summary>
    /// Verifica la password in chiaro rispetto all'hash memorizzato.
    /// </summary>
    public static bool Verify(string password, string hash)
        => BCrypt.Net.BCrypt.Verify(password, hash);
}

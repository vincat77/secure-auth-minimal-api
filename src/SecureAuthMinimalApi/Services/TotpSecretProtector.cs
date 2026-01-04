using Microsoft.AspNetCore.DataProtection;

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Protegge i segreti TOTP a riposo usando DataProtection.
/// </summary>
public sealed class TotpSecretProtector
{
    private readonly IDataProtector _protector;

    /// <summary>
    /// Inizializza il protector con il nome dello scudo per i segreti TOTP.
    /// </summary>
    public TotpSecretProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("totp_secret");
    }

    /// <summary>
    /// Protegge il segreto in chiaro e restituisce il ciphertext.
    /// </summary>
    public string Protect(string secret) => _protector.Protect(secret);

    /// <summary>
    /// Tenta di decriptare il ciphertext, altrimenti ritorna string.Empty.
    /// </summary>
    public string Unprotect(string cipherText)
    {
        try
        {
            return _protector.Unprotect(cipherText);
        }
        catch
        {
            return string.Empty;
        }
    }
}

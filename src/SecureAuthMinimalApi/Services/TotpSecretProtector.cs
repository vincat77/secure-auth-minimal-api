using Microsoft.AspNetCore.DataProtection;

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Protegge i segreti TOTP a riposo usando DataProtection.
/// </summary>
public sealed class TotpSecretProtector
{
    private readonly IDataProtector _protector;

    public TotpSecretProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("totp_secret");
    }

    public string Protect(string secret) => _protector.Protect(secret);

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

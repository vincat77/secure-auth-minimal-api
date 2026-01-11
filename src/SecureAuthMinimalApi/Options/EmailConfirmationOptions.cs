namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Configurazione per i requisiti di conferma email.
/// </summary>
public sealed class EmailConfirmationOptions
{
    /// <summary>
    /// Se true richiede che l'email sia confermata prima del login/altre operazioni che lo prevedono.
    /// </summary>
    public bool Required { get; set; } = true;
}

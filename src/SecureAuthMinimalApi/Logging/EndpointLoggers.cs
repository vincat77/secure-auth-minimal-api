namespace SecureAuthMinimalApi.Logging;

/// <summary>Marker logger per il login.</summary>
public sealed class LoginLogger;
/// <summary>Marker logger per la conferma MFA.</summary>
public sealed class ConfirmMfaLogger;
/// <summary>Marker logger per la conferma email.</summary>
public sealed class ConfirmEmailLogger;
/// <summary>Marker logger per il cambio email.</summary>
public sealed class ChangeEmailLogger;
/// <summary>Marker logger per il logout.</summary>
public sealed class LogoutLogger;
/// <summary>Marker logger per logout-all.</summary>
public sealed class LogoutAllLogger;
/// <summary>Marker logger per la disabilitazione MFA.</summary>
public sealed class MfaDisableLogger;
/// <summary>Marker logger per reset password.</summary>
public sealed class PasswordResetLogger;
/// <summary>Marker logger per introspezione token.</summary>
public sealed class IntrospectLogger;
/// <summary>Marker logger per registrazione utente.</summary>
public sealed class RegisterLogger;
/// <summary>Marker logger per refresh token/sessione.</summary>
public sealed class RefreshLogger;
/// <summary>Marker logger per endpoint ready.</summary>
public sealed class ReadyLogger;
/// <summary>Marker logger per endpoint live.</summary>
public sealed class LiveLogger;
/// <summary>Marker logger per endpoint health.</summary>
public sealed class HealthLogger;
/// <summary>Marker logger per endpoint /me.</summary>
public sealed class MeLogger;
/// <summary>Marker logger per setup MFA.</summary>
public sealed class MfaSetupLogger;

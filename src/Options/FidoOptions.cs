using System;

namespace SecureAuthMinimalApi.Options
{
    /// <summary>
    /// Configuration options for FIDO2 / WebAuthn integration.
    /// Bound from configuration section "Fido".
    /// </summary>
    public class FidoOptions
    {
        /// <summary>
        /// Relying Party identifier (RpId) - typically the domain (example.com).
        /// Must match the host used by the client requests.
        /// </summary>
        public string? RpId { get; set; }

        /// <summary>
        /// Origin accepted for WebAuthn (scheme://host[:port]), e.g. https://example.com.
        /// In production this must be HTTPS.
        /// </summary>
        public string? Origin { get; set; }

        /// <summary>
        /// Display name for the Relying Party shown to the user in the authenticator prompt.
        /// </summary>
        public string? RpName { get; set; }

        /// <summary>
        /// Challenge TTL in minutes. Default = 5.
        /// </summary>
        public int ChallengeTtlMinutes { get; set; } = 5;
    }
}
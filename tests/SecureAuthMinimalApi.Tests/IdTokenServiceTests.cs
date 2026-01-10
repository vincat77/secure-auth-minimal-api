using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureAuthMinimalApi.Options;
using SecureAuthMinimalApi.Services;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

public class IdTokenServiceTests
{
    private static IdTokenService CreateService(Dictionary<string, string?>? overrides = null)
    {
        var idOptions = new IdTokenOptions
        {
            Issuer = "TestIdIssuer",
            Audience = "TestIdAudience",
            Secret = "TEST_ID_TOKEN_SECRET_AT_LEAST_32_CHARS_LONG___"
        };
        var jwtOptions = new JwtOptions
        {
            Issuer = "FallbackIssuer",
            Audience = "FallbackAudience",
            SecretKey = "TEST_JWT_SECRET_AT_LEAST_32_CHARACTERS_LONG___"
        };

        if (overrides is not null)
        {
            foreach (var kv in overrides)
            {
                switch (kv.Key)
                {
                    case "IdToken:Issuer":
                        idOptions.Issuer = kv.Value;
                        break;
                    case "IdToken:Audience":
                        idOptions.Audience = kv.Value;
                        break;
                    case "IdToken:Secret":
                        idOptions.Secret = kv.Value;
                        break;
                    case "IdToken:SigningKeyPath":
                        idOptions.SigningKeyPath = kv.Value;
                        break;
                    case "Jwt:Issuer":
                        jwtOptions.Issuer = kv.Value ?? "";
                        break;
                    case "Jwt:Audience":
                        jwtOptions.Audience = kv.Value ?? "";
                        break;
                    case "Jwt:SecretKey":
                        jwtOptions.SecretKey = kv.Value ?? "";
                        break;
                }
            }
        }

        return new IdTokenService(Microsoft.Extensions.Options.Options.Create(idOptions), Microsoft.Extensions.Options.Options.Create(jwtOptions));
    }

    [Fact]
    public void CreateIdToken_includes_profile_claims()
    {
        // Scenario: genera un ID token popolando name, given_name, family_name, email e picture per verificare che vengano inclusi nei claim.
        // Risultato atteso: ID token contiene tutti i claim di profilo disponibili.
        var service = CreateService();

        var (token, _) = service.CreateIdToken(
            userId: "user-1",
            username: "alice",
            email: "alice@example.com",
            mfaConfirmed: true,
            nonce: "nonce123",
            minutes: 15,
            name: "Alice Doe",
            givenName: "Alice",
            familyName: "Doe",
            pictureUrl: "https://example.com/alice.png");

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        Assert.Equal("TestIdIssuer", jwt.Issuer);
        Assert.Contains("TestIdAudience", jwt.Audiences);
        Assert.Equal("alice@example.com", jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Email).Value);
        Assert.Equal("Alice Doe", jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Name).Value);
        Assert.Equal("Alice", jwt.Claims.First(c => c.Type == "given_name").Value);
        Assert.Equal("Doe", jwt.Claims.First(c => c.Type == "family_name").Value);
        Assert.Equal("alice", jwt.Claims.First(c => c.Type == "preferred_username").Value);
        Assert.Equal("https://example.com/alice.png", jwt.Claims.First(c => c.Type == "picture").Value);
        Assert.Contains(jwt.Claims, c => c.Type == JwtRegisteredClaimNames.Nonce && c.Value == "nonce123");
        Assert.Contains(jwt.Claims, c => c.Type == "amr" && c.Value == "mfa");
    }

    [Fact]
    public void CreateIdToken_allows_missing_email_and_picture()
    {
        // Scenario: costruisce un ID token senza email né picture per verificare che i claim opzionali possano mancare.
        // Risultato atteso: ID token valido senza i claim opzionali assenti.
        var service = CreateService();

        var (token, _) = service.CreateIdToken(
            userId: "user-2",
            username: "bob",
            email: null,
            mfaConfirmed: false,
            nonce: null,
            minutes: 10,
            name: "Bob Smith",
            givenName: "Bob",
            familyName: "Smith",
            pictureUrl: null);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        Assert.DoesNotContain(jwt.Claims, c => c.Type == JwtRegisteredClaimNames.Email);
        Assert.DoesNotContain(jwt.Claims, c => c.Type == "picture");
        Assert.Contains(jwt.Claims, c => c.Type == "amr" && c.Value == "pwd");
    }

    [Fact]
    public void CreateIdToken_uses_rsa_when_keypath_present()
    {
        // Scenario: configura un percorso di chiave RSA e genera un ID token per verificare la firma asimmetrica.
        // Risultato atteso: token firmato RSA validabile con la chiave pubblica.
        using var rsa = RSA.Create(2048);
        var pk = rsa.ExportRSAPrivateKey();
        var pem = "-----BEGIN RSA PRIVATE KEY-----\n" +
                  Convert.ToBase64String(pk, Base64FormattingOptions.InsertLineBreaks) +
                  "\n-----END RSA PRIVATE KEY-----";
        var path = Path.Combine(Path.GetTempPath(), $"idtoken-{Guid.NewGuid():N}.pem");
        File.WriteAllText(path, pem);

        try
        {
            var svc = CreateService(new Dictionary<string, string?> { ["IdToken:SigningKeyPath"] = path });
            var (token, _) = svc.CreateIdToken("user-3", "carol", "carol@example.com", mfaConfirmed: true, pictureUrl: null, name: "Carol", givenName: "Carol", familyName: "Smith");
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
            Assert.Equal(SecurityAlgorithms.RsaSha256, jwt.Header.Alg);
        }
        finally
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }

    [Fact]
    public void CreateIdToken_throws_on_short_secret()
    {
        // Scenario: prova a creare l'ID token con secret simmetrico troppo corto.
        // Risultato atteso: eccezione per secret insufficiente.
        var cfg = new IdTokenOptions
        {
            Issuer = "Issuer",
            Audience = "Audience",
            Secret = "short"
        };
        var jwt = new JwtOptions { Issuer = "Fallback", Audience = "Fallback", SecretKey = "THIS_IS_A_LONG_SECRET_KEY_32_CHARS_MIN" };

        Assert.Throws<InvalidOperationException>(() => new IdTokenService(Microsoft.Extensions.Options.Options.Create(cfg), Microsoft.Extensions.Options.Options.Create(jwt)));
    }
}

using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SecureAuthMinimalApi.Services;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

public class IdTokenServiceTests
{
    private static IdTokenService CreateService(Dictionary<string, string?>? overrides = null)
    {
        var data = new Dictionary<string, string?>
        {
            ["IdToken:Issuer"] = "TestIdIssuer",
            ["IdToken:Audience"] = "TestIdAudience",
            ["IdToken:Secret"] = "TEST_ID_TOKEN_SECRET_AT_LEAST_32_CHARS_LONG___",
            ["IdToken:IncludeEmail"] = "true",
            ["Jwt:Issuer"] = "FallbackIssuer",
            ["Jwt:Audience"] = "FallbackAudience",
            ["Jwt:SecretKey"] = "TEST_JWT_SECRET_AT_LEAST_32_CHARACTERS_LONG___"
        };

        if (overrides is not null)
        {
            foreach (var kv in overrides)
                data[kv.Key] = kv.Value;
        }

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(data)
            .Build();

        return new IdTokenService(config);
    }

    [Fact]
    public void CreateIdToken_includes_profile_claims()
    {
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
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["IdToken:Issuer"] = "Issuer",
                ["IdToken:Audience"] = "Audience",
                ["IdToken:Secret"] = "short"
            })
            .Build();

        Assert.Throws<InvalidOperationException>(() => new IdTokenService(cfg));
    }
}

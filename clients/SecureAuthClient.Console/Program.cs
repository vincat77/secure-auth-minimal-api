using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using SecureAuthClient;

var baseUrl = Environment.GetEnvironmentVariable("SECUREAUTH_BASEURL") ?? "https://localhost:52899";
var demoUser = Environment.GetEnvironmentVariable("SECUREAUTH_DEMO_USER") ?? "demo";
var demoPass = Environment.GetEnvironmentVariable("SECUREAUTH_DEMO_PASS") ?? "123456789012";
var unconfUser = Environment.GetEnvironmentVariable("SECUREAUTH_UNCONF_USER") ?? "smoke-unconfirmed";
var unconfPass = Environment.GetEnvironmentVariable("SECUREAUTH_UNCONF_PASS") ?? "Unconfirmed123!";
var perfLoginCount = int.TryParse(Environment.GetEnvironmentVariable("SECUREAUTH_PERF_LOGIN"), out var l) ? l : 20;
var perfRegisterCount = int.TryParse(Environment.GetEnvironmentVariable("SECUREAUTH_PERF_REGISTER"), out var r) ? r : 20;

var handler = new HttpClientHandler
{
    CookieContainer = new CookieContainer(),
    UseCookies = true,
    AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
};

var options = new SecureAuthClientOptions
{
    BaseUrl = baseUrl,
    UserAgent = "SecureAuthConsoleSmoke/1.0"
};

var api = new SecureAuthApiClient(options, handler);
var rawHttp = new HttpClient(handler) { BaseAddress = new Uri(baseUrl) };
rawHttp.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
rawHttp.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent);

Console.WriteLine($"Base URL: {baseUrl}");
Console.WriteLine("== Health ==");
await GetHealthAsync(rawHttp);

Console.WriteLine("\n== Login demo ==");
var loginDemo = await api.LoginAsync(demoUser, demoPass, rememberMe: true);
Assert(loginDemo.Ok, "Login demo");
Dump(loginDemo);

Console.WriteLine("\n== Refresh (demo) ==");
var refreshDemo = await api.RefreshAsync();
Assert(refreshDemo.Ok, "Refresh demo");
Dump(refreshDemo);

Console.WriteLine("\n== Refresh without header (expected failure) ==");
await RefreshManual(rawHttp, handler.CookieContainer, includeHeader: false);

Console.WriteLine("\n== Refresh with wrong header (expected failure) ==");
await RefreshManual(rawHttp, handler.CookieContainer, includeHeader: true, headerValue: "wrong");

Console.WriteLine("\n== Logout with CSRF (demo) ==");
var logout = await api.LogoutAsync();
Assert(logout.Ok, "Logout demo");
Dump(logout);

Console.WriteLine("\n== Login unconfirmed ==");
var loginUnconf = await api.LoginAsync(unconfUser, unconfPass, rememberMe: true);
Assert(loginUnconf.Ok, "Login unconfirmed");
Dump(loginUnconf);

Console.WriteLine("\n== Change email (unconfirmed) ==");
var newEmail = $"dev{Guid.NewGuid():N}".Substring(0, 10) + "@example.com";
var changeEmail = await api.ChangeEmailAsync(newEmail);
Assert(changeEmail.Ok, "Change email unconfirmed");
Dump(changeEmail);

Console.WriteLine("\n== Logout unconfirmed ==");
var logoutUnconf = await api.LogoutAsync();
Assert(logoutUnconf.Ok, "Logout unconfirmed");
Dump(logoutUnconf);

Console.WriteLine($"\n== Perf test (registrations={perfRegisterCount}, logins={perfLoginCount}) ==");
await RunPerfAsync(baseUrl, perfRegisterCount, perfLoginCount, options.UserAgent);

Console.WriteLine("\nSmoke console completato.");

static async Task GetHealthAsync(HttpClient http)
{
    var res = await http.GetAsync("/health");
    Console.WriteLine($"Health status: {(int)res.StatusCode}");
    res.EnsureSuccessStatusCode();
}

static async Task RefreshManual(HttpClient http, CookieContainer cookies, bool includeHeader, string? headerValue = null)
{
    using var req = new HttpRequestMessage(HttpMethod.Post, "/refresh");
    if (includeHeader)
    {
        req.Headers.Add("X-Refresh-Csrf", headerValue ?? string.Empty);
    }

    var resp = await http.SendAsync(req);
    Console.WriteLine($"Status: {(int)resp.StatusCode} {resp.StatusCode}");
    if (resp.IsSuccessStatusCode)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Console.WriteLine(body);
    }
}

static void Dump(object obj)
{
    var json = JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true });
    Console.WriteLine(json);
}

static void Assert(bool condition, string name)
{
    if (!condition)
    {
        throw new InvalidOperationException($"Assertion failed: {name}");
    }
}

static async Task RunPerfAsync(string baseUrl, int registrations, int logins, string userAgent)
{
    using var handler = new HttpClientHandler
    {
        CookieContainer = new CookieContainer(),
        UseCookies = true,
        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    };
    using var http = new HttpClient(handler) { BaseAddress = new Uri(baseUrl) };
    http.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
    http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

    if (registrations > 0)
    {
        var tasks = Enumerable.Range(0, registrations).Select(i =>
        {
            var username = $"perfuser{i}_{Guid.NewGuid():N}".Substring(0, 20);
            var payload = new
            {
                username,
                password = "PerfUser123!",
                email = $"{username}@example.com"
            };
            return http.PostAsync("/register", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        }).ToArray();

        await Task.WhenAll(tasks);
        var ok = tasks.Count(t => t.Result.IsSuccessStatusCode);
        Console.WriteLine($"Registrazioni completate: {ok}/{registrations}");
    }

    if (logins > 0)
    {
        var loginPayload = new { username = "demo", password = "123456789012", rememberMe = false };
        var tasks = Enumerable.Range(0, logins).Select(_ =>
            http.PostAsync("/login", new StringContent(JsonSerializer.Serialize(loginPayload), Encoding.UTF8, "application/json"))
        ).ToArray();
        await Task.WhenAll(tasks);
        var ok = tasks.Count(t => t.Result.IsSuccessStatusCode);
        Console.WriteLine($"Login completati: {ok}/{logins}");
    }
}

using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Reflection;
using System.Linq;
using WinFormsClient;
using WinFormsClient.Controls;
using Xunit;

namespace WinFormsClient.Tests;

public class MainFormChangePasswordTests
{
    [Fact]
    public async Task ChangePasswordAsync_sends_payload_and_updates_csrf_on_success()
    {
        // Scenario: il form WinForms invia la richiesta di cambio password con payload corretto e, su successo, aggiorna il token CSRF locale.
        // Risultato atteso: payload inviato, stato aggiornato e nuovo CSRF salvato.
        await RunStaAsync(async () =>
        {
            var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"ok\":true,\"csrfToken\":\"new-csrf\"}", Encoding.UTF8, "application/json")
            });

            using var form = new MainForm();
            SetField(form, "_http", new HttpClient(handler));
            SetField(form, "_csrfToken", "old-csrf");
            SetField(form, "_isAuthenticated", true);
            Assert.Equal("old-csrf", GetField<string?>(form, "_csrfToken"));

            var current = GetField<LabeledTextBoxControl>(form, "_currentPasswordInput");
            var next = GetField<LabeledTextBoxControl>(form, "_newPasswordInput");
            var confirm = GetField<LabeledTextBoxControl>(form, "_confirmPasswordInput");
            current.ValueText = "oldpass!";
            next.ValueText = "newpass!";
            confirm.ValueText = "newpass!";

            await InvokeChangePasswordAsync(form);

            Assert.NotNull(handler.LastRequest);
            Assert.True(handler.LastRequest!.Headers.TryGetValues("X-CSRF-Token", out var csrfValues), $"Header X-CSRF-Token mancante. Headers: {handler.HeadersDump ?? "<null>"}");
            Assert.Contains("old-csrf", csrfValues);
            Assert.Contains("\"currentPassword\":\"oldpass!\"", handler.LastContent);
            Assert.Contains("\"newPassword\":\"newpass!\"", handler.LastContent);
            Assert.Contains("\"confirmPassword\":\"newpass!\"", handler.LastContent);
            Assert.Equal("new-csrf", GetField<string?>(form, "_csrfToken"));
            Assert.Equal(string.Empty, current.ValueText);
            Assert.Equal(string.Empty, next.ValueText);
            Assert.Equal(string.Empty, confirm.ValueText);
        });
    }

    [Fact]
    public async Task ChangePasswordAsync_preserves_fields_on_failure()
    {
        // Scenario: la chiamata di cambio password fallisce (es. 400) e il form deve mantenere i valori inseriti dall'utente per consentire correzioni.
        // Risultato atteso: campi non vengono puliti e l'errore viene mostrato.
        await RunStaAsync(async () =>
        {
            var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("{\"ok\":false,\"error\":\"invalid_current_password\"}", Encoding.UTF8, "application/json")
            });

            using var form = new MainForm();
            SetField(form, "_http", new HttpClient(handler));
            SetField(form, "_csrfToken", "old-csrf");
            SetField(form, "_isAuthenticated", true);
            Assert.Equal("old-csrf", GetField<string?>(form, "_csrfToken"));

            var current = GetField<LabeledTextBoxControl>(form, "_currentPasswordInput");
            var next = GetField<LabeledTextBoxControl>(form, "_newPasswordInput");
            var confirm = GetField<LabeledTextBoxControl>(form, "_confirmPasswordInput");
            current.ValueText = "wrong";
            next.ValueText = "new-value";
            confirm.ValueText = "new-value";

            await InvokeChangePasswordAsync(form);

            Assert.NotNull(handler.LastRequest);
            Assert.True(handler.LastRequest!.Headers.TryGetValues("X-CSRF-Token", out var csrfValues), $"Header X-CSRF-Token mancante. Headers: {handler.HeadersDump ?? "<null>"}");
            Assert.Contains("old-csrf", csrfValues);
            Assert.Equal("old-csrf", GetField<string?>(form, "_csrfToken"));
            Assert.Equal("wrong", current.ValueText);
            Assert.Equal("new-value", next.ValueText);
            Assert.Equal("new-value", confirm.ValueText);
        });
    }

    [Fact]
    public async Task ChangePasswordAsync_handles_network_error_without_reset()
    {
        // Scenario: si verifica un errore di rete durante il submit; il form deve mostrare l'errore senza perdere i dati inseriti.
        // Risultato atteso: input preservati e stato coerente dopo l'eccezione di rete.
        await RunStaAsync(async () =>
        {
            var handler = new StubHandler(_ => throw new HttpRequestException("network fail"));

            using var form = new MainForm();
            SetField(form, "_http", new HttpClient(handler));
            SetField(form, "_csrfToken", "old-csrf");
            SetField(form, "_isAuthenticated", true);

            var current = GetField<LabeledTextBoxControl>(form, "_currentPasswordInput");
            var next = GetField<LabeledTextBoxControl>(form, "_newPasswordInput");
            var confirm = GetField<LabeledTextBoxControl>(form, "_confirmPasswordInput");
            current.ValueText = "old";
            next.ValueText = "new";
            confirm.ValueText = "new";

            await InvokeChangePasswordAsync(form);

            Assert.Equal("old", current.ValueText);
            Assert.Equal("new", next.ValueText);
            Assert.Equal("new", confirm.ValueText);
            Assert.Equal("old-csrf", GetField<string?>(form, "_csrfToken"));
        });
    }

    [Fact]
    public async Task ChangePassword_controls_enabled_only_when_authenticated()
    {
        // Scenario: verifica che i controlli di cambio password siano disabilitati senza sessione e diventino attivi dopo autenticazione simulata.
        // Risultato atteso: controlli abilitati solo quando l'utente è autenticato.
        await RunStaAsync(async () =>
        {
            using var form = new MainForm();
            var current = GetField<LabeledTextBoxControl>(form, "_currentPasswordInput");
            var next = GetField<LabeledTextBoxControl>(form, "_newPasswordInput");
            var confirm = GetField<LabeledTextBoxControl>(form, "_confirmPasswordInput");

            // default non autenticato
            Assert.False(current.Enabled);
            Assert.False(next.Enabled);
            Assert.False(confirm.Enabled);

            InvokePrivate(form, "ApplyChangePasswordEnabled", true);
            Assert.True(current.Enabled);
            Assert.True(next.Enabled);
            Assert.True(confirm.Enabled);
        });
    }

    private static Task InvokeChangePasswordAsync(MainForm form)
    {
        var method = typeof(MainForm).GetMethod("ChangePasswordAsync", BindingFlags.NonPublic | BindingFlags.Instance);
        var task = method!.Invoke(form, Array.Empty<object>()) as Task;
        return task ?? Task.CompletedTask;
    }

    private static T GetField<T>(object target, string name)
    {
        var field = target.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance);
        return (T)(field?.GetValue(target) ?? throw new InvalidOperationException($"Field {name} not found"));
    }

    private static void SetField<T>(object target, string name, T value)
    {
        var field = target.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance);
        if (field is null) throw new InvalidOperationException($"Field {name} not found");
        field.SetValue(target, value);
    }

    private static void InvokePrivate(object target, string name, params object[] args)
    {
        var method = target.GetType().GetMethod(name, BindingFlags.NonPublic | BindingFlags.Instance);
        if (method is null) throw new InvalidOperationException($"Method {name} not found");
        method.Invoke(target, args);
    }

    private static Task RunStaAsync(Func<Task> action)
    {
        var tcs = new TaskCompletionSource<bool>();
        var thread = new Thread(() =>
        {
            try
            {
                action().GetAwaiter().GetResult();
                tcs.SetResult(true);
            }
            catch (Exception ex)
            {
                tcs.SetException(ex);
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return tcs.Task;
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

        public HttpRequestMessage? LastRequest { get; private set; }
        public string? LastContent { get; private set; }
        public string? HeadersDump { get; private set; }

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            _responder = responder;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            if (request.Content is not null)
            {
                LastContent = request.Content.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult();
            }
            HeadersDump = request.Headers.ToString();

            return Task.FromResult(_responder(request));
        }
    }
}

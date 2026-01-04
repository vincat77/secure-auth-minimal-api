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

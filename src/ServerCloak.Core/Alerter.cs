using System.Net;
using System.Net.Http.Json;
using System.Net.Mail;
using System.Text.Json;

namespace ServerCloak.Core;

public enum AlertKind
{
    Block,
    Spike,
    ServiceStop,
    RealAccount,
    Health,
    DailySummary,
    Test
}

/// <summary>Alert settings. Secrets are stored encrypted with DPAPI.</summary>
public class AlertSettings
{
    public string SmtpHost { get; set; } = "";
    public int SmtpPort { get; set; } = 587;
    public bool SmtpSsl { get; set; } = true;
    public string SmtpUser { get; set; } = "";
    public string SmtpPassword { get; set; } = "";
    public string MailFrom { get; set; } = "";
    public string MailTo { get; set; } = "";
    /// <summary>Slack incoming webhook, Teams workflow webhook, or any URL that accepts a JSON post.</summary>
    public string WebhookUrl { get; set; } = "";

    public bool OnBlock { get; set; }
    public bool OnSpike { get; set; } = true;
    public bool OnServiceStop { get; set; } = true;
    public bool OnRealAccount { get; set; } = true;
    public bool OnHealth { get; set; } = true;
    public bool DailySummary { get; set; } = true;

    public int SpikeBlocks { get; set; } = 20;
    public int SpikeMinutes { get; set; } = 10;
    public int SummaryHour { get; set; } = 8;

    public bool HasEmail => SmtpHost.Length > 0 && MailTo.Length > 0;
    public bool HasWebhook => WebhookUrl.Length > 0;

    private const string Key = "Alerts";
    private const string SecretKey = "AlertSecrets";

    public static AlertSettings Load()
    {
        AlertSettings s;
        try { s = JsonSerializer.Deserialize<AlertSettings>(CloakStore.GetSetting(Key) ?? "{}") ?? new(); }
        catch { s = new(); }
        var secrets = CloakStore.GetSecret(SecretKey).Split('\n');
        s.SmtpPassword = secrets.Length > 0 ? secrets[0] : "";
        s.WebhookUrl = secrets.Length > 1 ? secrets[1] : "";
        return s;
    }

    public void Save()
    {
        var copy = (AlertSettings)MemberwiseClone();
        copy.SmtpPassword = "";
        copy.WebhookUrl = "";
        CloakStore.SetSetting(Key, JsonSerializer.Serialize(copy));
        CloakStore.SetSecret(SecretKey, $"{SmtpPassword}\n{WebhookUrl}");
    }

    public bool Wants(AlertKind kind) => kind switch
    {
        AlertKind.Block => OnBlock,
        AlertKind.Spike => OnSpike,
        AlertKind.ServiceStop => OnServiceStop,
        AlertKind.RealAccount => OnRealAccount,
        AlertKind.Health => OnHealth,
        AlertKind.DailySummary => DailySummary,
        _ => true
    };
}

/// <summary>Sends alerts to the tray (through the logs database), email and a Slack or Teams webhook.</summary>
public static class Alerter
{
    public static async Task SendAsync(AlertKind kind, string title, string text, CancellationToken ct = default)
    {
        var level = kind switch
        {
            AlertKind.Block => NotificationLevel.Block,
            AlertKind.DailySummary => NotificationLevel.Summary,
            AlertKind.Test => NotificationLevel.Info,
            _ => NotificationLevel.Warning
        };
        if (kind != AlertKind.Test)
            CloakStore.AddNotification(level, title, text);

        var s = AlertSettings.Load();
        if (!s.Wants(kind))
            return;
        var errors = await SendRemoteAsync(s, title, text, ct);
        if (errors.Count > 0)
            AppPaths.LogError("Alert", new InvalidOperationException(string.Join("; ", errors)));
    }

    /// <summary>Sends to email and webhook. Returns the errors, empty when everything worked.</summary>
    public static async Task<List<string>> SendRemoteAsync(AlertSettings s, string title, string text, CancellationToken ct = default)
    {
        var errors = new List<string>();
        var subject = $"ServerCloak on {Environment.MachineName}: {title}";
        if (s.HasEmail)
        {
            try { await SendEmailAsync(s, subject, text, ct); }
            catch (Exception ex) { errors.Add("Email: " + ex.Message); }
        }
        if (s.HasWebhook)
        {
            try { await SendWebhookAsync(s.WebhookUrl, subject, text, ct); }
            catch (Exception ex) { errors.Add("Webhook: " + ex.Message); }
        }
        return errors;
    }

    private static async Task SendEmailAsync(AlertSettings s, string subject, string text, CancellationToken ct)
    {
        using var client = new SmtpClient(s.SmtpHost, s.SmtpPort) { EnableSsl = s.SmtpSsl, DeliveryMethod = SmtpDeliveryMethod.Network, Timeout = 30000 };
        if (s.SmtpUser.Length > 0)
            client.Credentials = new NetworkCredential(s.SmtpUser, s.SmtpPassword);
        var from = s.MailFrom.Length > 0 ? s.MailFrom : s.SmtpUser;
        using var message = new MailMessage { From = new MailAddress(from, "ServerCloak"), Subject = subject, Body = text };
        foreach (var to in s.MailTo.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            message.To.Add(to);
        await client.SendMailAsync(message, ct);
    }

    private static async Task SendWebhookAsync(string url, string subject, string text, CancellationToken ct)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        object payload;
        if (url.Contains("hooks.slack.com", StringComparison.OrdinalIgnoreCase))
            payload = new { text = $"*{subject}*\n{text}" };
        else if (url.Contains("discord.com/api/webhooks", StringComparison.OrdinalIgnoreCase))
            payload = new { content = $"**{subject}**\n{text}" };
        else
            // Teams workflows ("When a Teams webhook request is received") expect an Adaptive Card attachment.
            payload = new
            {
                type = "message",
                text = subject,
                attachments = new[]
                {
                    new
                    {
                        contentType = "application/vnd.microsoft.card.adaptive",
                        content = new Dictionary<string, object>
                        {
                            ["$schema"] = "http://adaptivecards.io/schemas/adaptive-card.json",
                            ["type"] = "AdaptiveCard",
                            ["version"] = "1.4",
                            ["body"] = new object[]
                            {
                                new { type = "TextBlock", text = subject, weight = "Bolder", wrap = true },
                                new { type = "TextBlock", text, wrap = true }
                            }
                        }
                    }
                }
            };
        using var resp = await http.PostAsJsonAsync(url, payload, ct);
        resp.EnsureSuccessStatusCode();
    }
}

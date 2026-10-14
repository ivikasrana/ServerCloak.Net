using System.Text.Json;
using System.Text.Json.Serialization;

namespace ServerCloak.Core;

/// <summary>Exports and imports settings as JSON so other servers can use the same setup. Secrets are never exported.</summary>
public static class SettingsBackup
{
    private static readonly string[] SettingKeys =
    [
        CloakStore.KeyUseDynamicKeywords, CloakStore.KeyEscalation, CloakStore.KeyEscalationSteps, CloakStore.KeyDryRun,
        CloakStore.KeyHealthHours, CloakStore.KeyLogRetentionDays, CloakStore.KeyCountryMode, CloakStore.KeyFeedHours,
        CloakStore.KeyAbuseIpDbReport, CloakStore.KeyUpdateRepo, CloakStore.KeyTrayEnabled, CloakStore.KeyTrayPopups, CloakStore.KeyTheme
    ];

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public class Backup
    {
        public string App { get; set; } = "ServerCloak";
        public string Version { get; set; } = AppPaths.Version;
        public string Machine { get; set; } = Environment.MachineName;
        public DateTime Exported { get; set; } = DateTime.Now;
        public List<CloakSetting> Cloaks { get; set; } = [];
        public List<string> Whitelist { get; set; } = [];
        public List<string> Countries { get; set; } = [];
        public List<FeedSource> Feeds { get; set; } = [];
        public Dictionary<string, string> Settings { get; set; } = [];
        public AlertSettings? Alerts { get; set; }
    }

    public static string Export()
    {
        var settings = CloakStore.GetAllSettings();
        var alerts = AlertSettings.Load();
        alerts.SmtpPassword = "";
        alerts.WebhookUrl = "";
        var backup = new Backup
        {
            Cloaks = CloakStore.GetCloaks(),
            Whitelist = CloakStore.GetWhitelist(),
            Countries = CloakStore.GetCountryRules(),
            Feeds = CloakStore.GetFeeds().Select(f => new FeedSource { Name = f.Name, Url = f.Url, Format = f.Format, Enabled = f.Enabled }).ToList(),
            Settings = SettingKeys.Where(settings.ContainsKey).ToDictionary(k => k, k => settings[k]),
            Alerts = alerts
        };
        return JsonSerializer.Serialize(backup, Options);
    }

    /// <summary>Imports a backup. The whitelist is merged; everything else replaces the current values. Returns a summary.</summary>
    public static string Import(string json)
    {
        var b = JsonSerializer.Deserialize<Backup>(json, Options) ?? throw new FormatException("The file is empty.");
        if (b.App != "ServerCloak")
            throw new FormatException("This is not a ServerCloak settings file.");

        var current = CloakStore.GetCloaks().ToDictionary(x => x.Id);
        CloakStore.SaveCloaks(b.Cloaks.Where(x => !x.IsCustom && current.ContainsKey(x.Id)));
        // Custom rules are matched by name so ids on this server stay free.
        var customByName = current.Values.Where(x => x.IsCustom).ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
        foreach (var c in b.Cloaks.Where(x => x.IsCustom))
        {
            c.Id = customByName.TryGetValue(c.Name, out var existing) ? existing.Id : 0;
            CloakStore.SaveCustomCloak(c);
        }

        var whitelist = CloakStore.GetWhitelist();
        foreach (var w in b.Whitelist.Where(w => !whitelist.Contains(w, StringComparer.OrdinalIgnoreCase)))
            whitelist.Add(w);
        CloakStore.SaveWhitelist(whitelist);

        var mode = b.Settings.TryGetValue(CloakStore.KeyCountryMode, out var m) && Enum.TryParse<CountryMode>(m, out var cm) ? cm : CloakStore.GetCountryMode();
        CloakStore.SaveCountryRules(mode, b.Countries);

        var feeds = CloakStore.GetFeeds();
        foreach (var f in b.Feeds)
        {
            var match = feeds.FirstOrDefault(x => x.Url.Equals(f.Url, StringComparison.OrdinalIgnoreCase));
            if (match != null)
                match.Enabled = f.Enabled;
            else
                feeds.Add(new FeedSource { Name = f.Name, Url = f.Url, Format = f.Format, Enabled = f.Enabled });
        }
        CloakStore.SaveFeeds(feeds);

        foreach (var (k, v) in b.Settings.Where(x => SettingKeys.Contains(x.Key)))
            CloakStore.SetSetting(k, v);

        if (b.Alerts != null)
        {
            var keep = AlertSettings.Load();
            b.Alerts.SmtpPassword = keep.SmtpPassword;
            b.Alerts.WebhookUrl = keep.WebhookUrl;
            b.Alerts.Save();
        }

        return $"Imported {b.Cloaks.Count} cloaks, {b.Whitelist.Count} whitelist entries, {b.Countries.Count} countries and {b.Feeds.Count} block lists from {b.Machine}.";
    }
}

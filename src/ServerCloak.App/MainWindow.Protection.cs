using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using ServerCloak.Core;

namespace ServerCloak.App;

public partial class MainWindow
{
    // Firewall and geo

    private async void FirewallOn_Click(object sender, RoutedEventArgs e) => await RunBusy(async () =>
    {
        await Task.Run(() => FirewallPolicyManager.Instance.EnsureFirewallEnabled());
        ShowToast("Windows Firewall turned on");
    });

    private async void DynamicKeyword_Click(object sender, RoutedEventArgs e)
    {
        bool on = DynamicKeywordSwitch.IsChecked == true;
        await RunBusy(async () =>
        {
            await Task.Run(() =>
            {
                CloakStore.SetBool(CloakStore.KeyUseDynamicKeywords, on);
                BlockEngine.SyncIps();
            });
            ShowToast(FirewallPolicyManager.Instance.Mode.StartsWith("Dynamic") || !on
                ? $"Block mode: {FirewallPolicyManager.Instance.Mode}"
                : "Dynamic keywords could not be used, firewall rules are used instead");
        });
    }

    private async void GeoUpdate_Click(object sender, RoutedEventArgs e) => await RunBusy(async () =>
    {
        GeoButton.IsEnabled = false;
        GeoText.Text = "Downloading…";
        try
        {
            var count = await Task.Run(() => GeoIp.UpdateAsync());
            if (CloakStore.GetCountryMode() != CountryMode.Off)
                await Task.Run(BlockEngine.SyncRanges);
            ShowToast($"Country data updated ({count:N0} ranges)");
        }
        finally
        {
            GeoButton.IsEnabled = true;
        }
    });

    // Country blocking

    private void ApplyCountrySearch()
    {
        var q = CountrySearch.Text.Trim();
        CountryPickList.ItemsSource = q.Length == 0 ? _countries
            : _countries.Where(c => c.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || c.Code.Equals(q, StringComparison.OrdinalIgnoreCase)).ToList();
        UpdateCountrySummary();
    }

    private void UpdateCountrySummary()
    {
        var picked = _countries.Where(x => x.Selected).Select(x => x.Code).ToList();
        CountrySelected.Text = picked.Count == 0 ? "No countries selected" : $"{picked.Count} selected: {string.Join(", ", picked.Take(12))}{(picked.Count > 12 ? "…" : "")}";
    }

    private void CountrySearch_TextChanged(object sender, TextChangedEventArgs e) => ApplyCountrySearch();
    private void CountryPick_Click(object sender, RoutedEventArgs e) => UpdateCountrySummary();

    private async void ApplyCountries_Click(object sender, RoutedEventArgs e)
    {
        var mode = CountryModeBox.SelectedValue is CountryMode m ? m : CountryMode.Off;
        var codes = _countries.Where(x => x.Selected).Select(x => x.Code).ToList();
        if (mode != CountryMode.Off && codes.Count == 0)
        {
            ShowError("Pick at least one country first.");
            return;
        }
        if (mode != CountryMode.Off && GeoIp.RangeCount() == 0)
        {
            ShowError("The country data has not been downloaded yet. Use Update now on the Country data card first.");
            return;
        }
        if (mode == CountryMode.AllowListed && !Confirm(
                $"Every address outside {string.Join(", ", codes)} will be blocked, including you when you travel or use a VPN abroad. " +
                "Whitelisted addresses, private networks and signed-in Remote Desktop clients stay allowed.\n\nContinue?"))
            return;

        await RunBusy(async () =>
        {
            var r = await Task.Run(() =>
            {
                CloakStore.SaveCountryRules(mode, codes);
                return BlockEngine.SyncRanges();
            });
            ShowToast(mode == CountryMode.Off ? "Country blocking off" : $"Country blocking applied ({r.CountryRanges:N0} ranges)");
        });
    }

    // Block lists

    private async void SaveFeeds_Click(object sender, RoutedEventArgs e) => await RunBusy(async () =>
    {
        int hours = ParseInt(FeedHoursBox, "Refresh hours", 1, 168);
        var key = AbuseKeyBox.Password.Trim();
        bool report = AbuseReportSwitch.IsChecked == true;
        if (report && key.Length == 0)
            throw new ArgumentException("Reporting to AbuseIPDB needs an API key.");
        if (_feeds.Any(f => f.Enabled && f.Format == FeedFormat.AbuseIpDb) && key.Length == 0)
            throw new ArgumentException("The AbuseIPDB blacklist needs an API key.");
        var feeds = _feeds.Select(f => f.ToSource()).ToList();
        await Task.Run(() =>
        {
            CloakStore.SaveFeeds(feeds);
            CloakStore.SetSecret(CloakStore.KeyAbuseIpDbKey, key);
            CloakStore.SetBool(CloakStore.KeyAbuseIpDbReport, report);
            CloakStore.SetInt(CloakStore.KeyFeedHours, hours);
            BlockEngine.SyncRanges();
        });
        LoadFeeds();
        ShowToast("Block lists saved. Use Update now to download them.");
    });

    private async void UpdateFeeds_Click(object sender, RoutedEventArgs e) => await RunBusy(async () =>
    {
        FeedUpdateButton.IsEnabled = false;
        try
        {
            CloakStore.SaveFeeds(_feeds.Select(f => f.ToSource()));
            var summary = await Task.Run(() => BlockFeeds.UpdateAllAsync());
            var r = await Task.Run(BlockEngine.SyncRanges);
            LoadFeeds();
            ShowToast($"{summary}, {r.Entries:N0} ranges in the firewall");
        }
        finally
        {
            FeedUpdateButton.IsEnabled = true;
        }
    });

    private void AddFeed_Click(object sender, RoutedEventArgs e)
    {
        var url = FeedUrlBox.Text.Trim();
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http"))
        {
            ShowError("Enter the http or https address of the list.");
            return;
        }
        var name = FeedNameBox.Text.Trim() is { Length: > 0 } n ? n : uri.Host;
        _feeds.Add(new FeedRow(new FeedSource { Name = name, Url = url, Format = FeedFormat.Text, Enabled = true }));
        FeedList.ItemsSource = null;
        FeedList.ItemsSource = _feeds;
        FeedNameBox.Text = FeedUrlBox.Text = "";
        ShowToast("List added. Save block lists to keep it.");
    }

    private void RemoveFeed_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not FeedRow row || !Confirm($"Remove '{row.Name}'?"))
            return;
        _feeds.Remove(row);
        FeedList.ItemsSource = null;
        FeedList.ItemsSource = _feeds;
        ShowToast("Removed. Save block lists to apply.");
    }

    private async void TestAbuseKey_Click(object sender, RoutedEventArgs e)
    {
        var key = AbuseKeyBox.Password.Trim();
        if (key.Length == 0)
        {
            ShowError("Enter the API key first.");
            return;
        }
        await RunBusy(async () => ShowError(await BlockFeeds.TestKeyAsync(key)));
    }

    // Alerts

    private AlertSettings ReadAlerts() => new()
    {
        SmtpHost = SmtpHostBox.Text.Trim(),
        SmtpPort = ParseInt(SmtpPortBox, "The SMTP port", 1, 65535),
        SmtpSsl = SmtpSslSwitch.IsChecked == true,
        SmtpUser = SmtpUserBox.Text.Trim(),
        SmtpPassword = SmtpPasswordBox.Password,
        MailFrom = MailFromBox.Text.Trim(),
        MailTo = MailToBox.Text.Trim(),
        WebhookUrl = WebhookBox.Password.Trim(),
        OnBlock = OnBlockBox.IsChecked == true,
        OnServiceStop = OnServiceStopBox.IsChecked == true,
        OnRealAccount = OnRealAccountBox.IsChecked == true,
        OnHealth = OnHealthBox.IsChecked == true,
        OnSpike = OnSpikeBox.IsChecked == true,
        SpikeBlocks = ParseInt(SpikeBlocksBox, "Spike blocks", 2, 10000),
        SpikeMinutes = ParseInt(SpikeMinutesBox, "Spike minutes", 1, 1440),
        DailySummary = DailySummaryBox.IsChecked == true,
        SummaryHour = ParseInt(SummaryHourBox, "The summary hour", 0, 23)
    };

    private async void SaveAlerts_Click(object sender, RoutedEventArgs e) => await RunBusy(async () =>
    {
        var s = ReadAlerts();
        if (s.WebhookUrl.Length > 0 && !Uri.TryCreate(s.WebhookUrl, UriKind.Absolute, out _))
            throw new ArgumentException("The webhook URL is not valid.");
        await Task.Run(s.Save);
        ShowToast("Alerts saved");
    });

    private async void TestAlert_Click(object sender, RoutedEventArgs e) => await RunBusy(async () =>
    {
        var s = ReadAlerts();
        if (!s.HasEmail && !s.HasWebhook)
            throw new ArgumentException("Enter an SMTP server and recipient, or a webhook URL, first.");
        var errors = await Alerter.SendRemoteAsync(s, "Test alert", $"This is a test from ServerCloak {AppPaths.Version} on {Environment.MachineName}.");
        if (errors.Count > 0)
            throw new InvalidOperationException(string.Join("\n", errors));
        ShowToast("Test alert sent");
    });

    // Protection

    private async void SaveProtection_Click(object sender, RoutedEventArgs e) => await RunBusy(async () =>
    {
        var steps = EscalationBox.Text.Trim();
        if (CloakStore.ParseSteps(steps).Count == 0)
            throw new ArgumentException("Enter at least one escalation step, for example 1h, 1d, permanent.");
        int health = ParseInt(HealthHoursBox, "Health hours", 0, 720);
        int retention = ParseInt(RetentionBox, "Log days", 7, 3650);
        bool dryRun = DryRunSwitch.IsChecked == true;
        bool changedDryRun = dryRun != BlockEngine.DryRun;
        await Task.Run(() =>
        {
            CloakStore.SetBool(CloakStore.KeyEscalation, EscalationSwitchValue);
            CloakStore.SetSetting(CloakStore.KeyEscalationSteps, steps);
            CloakStore.SetInt(CloakStore.KeyHealthHours, health);
            CloakStore.SetInt(CloakStore.KeyLogRetentionDays, retention);
            CloakStore.SetBool(CloakStore.KeyDryRun, dryRun);
            if (changedDryRun)
                BlockEngine.SyncAll();
        });
        ShowToast(changedDryRun ? (dryRun ? "Test mode on: firewall rules removed" : "Test mode off: blocks applied") : "Protection settings saved");
    });

    private bool EscalationSwitchValue => EscalationSwitch.IsChecked == true;

    private async void DryRunOff_Click(object sender, RoutedEventArgs e) => await RunBusy(async () =>
    {
        await Task.Run(() =>
        {
            CloakStore.SetBool(CloakStore.KeyDryRun, false);
            BlockEngine.SyncAll();
        });
        DryRunSwitch.IsChecked = false;
        ShowToast("Test mode off: blocks applied");
    });

    private async void ClearLogs_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm("Delete the attack history and notifications? Blocks, cloaks and settings are kept."))
            return;
        await RunBusy(async () =>
        {
            await Task.Run(CloakStore.ClearLogs);
            ShowToast("Logs cleared");
        });
    }
}

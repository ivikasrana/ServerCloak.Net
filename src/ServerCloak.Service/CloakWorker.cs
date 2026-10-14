using System.Globalization;
using System.Text;
using ServerCloak.Core;
using ServerCloak.Service.Cloaks;

namespace ServerCloak.Service;

public class CloakWorker(ILogger<CloakWorker> logger, ILoggerFactory loggerFactory) : BackgroundService
{
    private const string KeyLastSummary = "LastSummary";

    private readonly List<Cloak> _cloaks = [];
    private readonly object _blockLock = new();
    private readonly Queue<DateTime> _recentBlocks = new();
    private readonly Dictionary<string, DateTime> _realAccountAlerts = new(StringComparer.OrdinalIgnoreCase);
    private readonly DateTime _started = DateTime.Now;
    private DateTime _lastSpikeAlert = DateTime.MinValue;
    private bool _healthAlerted;
    private CancellationToken _stopping;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _stopping = stoppingToken;
        CloakStore.Initialize();
        logger.LogInformation("ServerCloak {Version} starting on {Os} (build {Build}).", AppPaths.Version, OsInfo.ProductName, OsInfo.Build);

        if (CloakStore.GetSetting(CloakStore.KeyCleanShutdown) == "false")
            await Alert(AlertKind.ServiceStop, "Service recovered", "The ServerCloak service stopped unexpectedly and has started again.");
        CloakStore.SetBool(CloakStore.KeyCleanShutdown, false);

        if (BlockEngine.DryRun)
            logger.LogWarning("Test mode is on: attacks are recorded but nothing is blocked.");

        SyncIps();
        _ = Task.Run(SyncRanges, stoppingToken);

        var failed = new List<string>();
        foreach (var setting in CloakStore.GetCloaks().Where(x => x.Enabled))
        {
            Cloak? cloak;
            try { cloak = CloakFactory.Create(setting, loggerFactory.CreateLogger($"ServerCloak.{setting.Name}")); }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Cloak {Cloak} has an invalid setup.", setting.Name);
                failed.Add(setting.Name);
                continue;
            }
            if (cloak == null)
                continue;
            cloak.AttackDetected += OnAttackDetected;
            try
            {
                cloak.Start();
                _cloaks.Add(cloak);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Cloak {Cloak} could not start.", setting.Name);
                failed.Add(setting.Name);
            }
        }
        logger.LogInformation("ServerCloak started {Count} cloaks: {Names}. Block mode: {Mode}.",
            _cloaks.Count, string.Join(", ", _cloaks.Select(x => x.Setting.Name)), FirewallPolicyManager.Instance.Mode);
        if (failed.Count > 0)
            await Alert(AlertKind.Health, "Cloaks did not start", "These cloaks could not start: " + string.Join(", ", failed) + ". See the Application event log for details.");

        _ = Task.Run(() => HourlyAsync(stoppingToken), stoppingToken);

        var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        int ticks = 0;
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                ticks++;
                try
                {
                    if (FirewallPolicyManager.Instance.EnsureFirewallEnabled())
                    {
                        logger.LogWarning("Windows Firewall was off for at least one profile and has been turned back on.");
                        await Alert(AlertKind.Health, "Firewall turned back on", "Windows Firewall was off for at least one profile and has been turned back on.");
                    }
                }
                catch (Exception ex) { logger.LogError(ex, "Firewall check failed."); }

                if (ticks % 2 == 0)
                {
                    try
                    {
                        if (CloakStore.ExpireBlocks())
                            SyncIps();
                    }
                    catch (Exception ex) { logger.LogError(ex, "Expiring blocks failed."); }

                    // The app sets this flag when country or block list settings change while it cannot reach the firewall.
                    if (CloakStore.GetSetting(CloakStore.KeyRangesChanged) == "true")
                    {
                        CloakStore.SetBool(CloakStore.KeyRangesChanged, false);
                        _ = Task.Run(SyncRanges, stoppingToken);
                    }
                }

                if (ticks % 10 == 0)
                {
                    await CheckHealthAsync();
                    await DailySummaryAsync();
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        foreach (var cloak in _cloaks)
        {
            try { cloak.Stop(); }
            catch (Exception ex) { logger.LogWarning(ex, "Cloak {Cloak} did not stop cleanly.", cloak.Setting.Name); }
        }
        _cloaks.Clear();

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            await Alerter.SendAsync(AlertKind.ServiceStop, "Service stopped", "The ServerCloak service was stopped. Attacks are not being blocked.", cts.Token);
        }
        catch (Exception ex) { logger.LogWarning(ex, "Sending the stop alert failed."); }
        CloakStore.SetBool(CloakStore.KeyCleanShutdown, true);
        await base.StopAsync(cancellationToken);
    }

    private void OnAttackDetected(AttackDetectedEventArgs data)
    {
        try
        {
            var result = CloakStore.RecordAttack(data);
            if (result.Ignored)
                return;

            if (data.RealAccount && !string.IsNullOrEmpty(data.Username))
                RealAccountTargeted(data);

            if (!result.Blocked)
                return;

            var name = CloakName(data.CloakName);
            var until = result.Expires == null ? "permanently" : $"until {result.Expires:dd MMM HH:mm}";
            var country = GeoIp.Lookup(result.Ip);
            logger.LogWarning("Blocking {Ip} {Until}: limit reached for {Cloak} (strike {Strikes}).", result.Ip, until, name, result.Strikes);
            SyncIps();

            var text = $"{result.Ip}{(country != null ? $" ({GeoIp.CountryName(country)})" : "")} blocked {until} after failed {name} logins"
                       + (result.Strikes > 1 ? $", strike {result.Strikes}." : ".")
                       + (BlockEngine.DryRun ? " Test mode: not blocked in the firewall." : "");
            _ = Alert(AlertKind.Block, "Address blocked", text);
            _ = ReportAsync(result.Ip, data.CloakName, name);
            CheckSpike();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Handling attack from {Ip} ({Cloak}) failed.", data.IpAddress, data.CloakName);
        }
    }

    private void RealAccountTargeted(AttackDetectedEventArgs data)
    {
        var user = data.Username!;
        lock (_realAccountAlerts)
        {
            if (_realAccountAlerts.TryGetValue(user, out var last) && DateTime.Now - last < TimeSpan.FromHours(1))
                return;
            _realAccountAlerts[user] = DateTime.Now;
        }
        logger.LogWarning("A real account is being targeted: {User} from {Ip} ({Cloak}).", user, data.IpAddress, data.CloakName);
        _ = Alert(AlertKind.RealAccount, "Real account targeted",
            $"Wrong passwords were tried for the existing account '{user}' from {data.IpAddress} ({CloakName(data.CloakName)}). Check that the password is strong and consider renaming or locking the account.");
    }

    private void CheckSpike()
    {
        var s = AlertSettings.Load();
        var now = DateTime.Now;
        lock (_recentBlocks)
        {
            _recentBlocks.Enqueue(now);
            while (_recentBlocks.Count > 0 && now - _recentBlocks.Peek() > TimeSpan.FromMinutes(Math.Max(1, s.SpikeMinutes)))
                _recentBlocks.Dequeue();
            if (_recentBlocks.Count < Math.Max(2, s.SpikeBlocks) || now - _lastSpikeAlert < TimeSpan.FromHours(1))
                return;
            _lastSpikeAlert = now;
        }
        logger.LogWarning("Block spike: {Count} addresses blocked in {Minutes} minutes.", s.SpikeBlocks, s.SpikeMinutes);
        _ = Alert(AlertKind.Spike, "Attack spike", $"{s.SpikeBlocks} or more addresses were blocked in the last {s.SpikeMinutes} minutes.");
    }

    private async Task ReportAsync(string ip, CloakEnum cloak, string name)
    {
        try
        {
            var attempts = CloakStore.GetIpLogs(cloak, false, ip, 0, 1).Rows.FirstOrDefault()?.Attacks ?? 0;
            await BlockFeeds.ReportAsync(ip, cloak, name, attempts, _stopping);
        }
        catch (Exception ex) { logger.LogWarning(ex, "Reporting {Ip} to AbuseIPDB failed.", ip); }
    }

    private async Task CheckHealthAsync()
    {
        try
        {
            int hours = CloakStore.GetInt(CloakStore.KeyHealthHours, 24);
            if (hours <= 0 || _cloaks.Count == 0)
                return;
            var last = CloakStore.GetLastEventTime() ?? DateTime.MinValue;
            var since = last > _started ? last : _started;
            if (DateTime.Now - since < TimeSpan.FromHours(hours))
            {
                _healthAlerted = false;
                return;
            }
            if (_healthAlerted)
                return;
            _healthAlerted = true;
            var text = $"No failed logins were seen for {hours} hours. On an internet-facing server this usually means a log, audit policy or cloak stopped working. Check that auditing of logon failures is on and the cloaks are running.";
            logger.LogWarning("Health check: {Text}", text);
            await Alert(AlertKind.Health, "No attacks seen", text);
        }
        catch (Exception ex) { logger.LogWarning(ex, "Health check failed."); }
    }

    private async Task DailySummaryAsync()
    {
        try
        {
            var s = AlertSettings.Load();
            var today = DateTime.Today.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            if (DateTime.Now.Hour < s.SummaryHour || CloakStore.GetSetting(KeyLastSummary) == today)
                return;
            CloakStore.SetSetting(KeyLastSummary, today);

            var since = DateTime.Now.AddDays(-1);
            var events = CloakStore.GetEvents(since);
            var sb = new StringBuilder();
            sb.AppendLine($"Last 24 hours: {events.Count:N0} failed attempts from {events.Select(x => x.Ip).Distinct().Count():N0} addresses, {events.Count(x => x.Blocked):N0} new blocks.");
            sb.AppendLine($"Blocked now: {CloakStore.GetBlockedCount():N0} addresses.{(BlockEngine.DryRun ? " Test mode is on." : "")}");
            var byCloak = events.GroupBy(x => x.Cloak).OrderByDescending(g => g.Count()).Take(5).Select(g => $"{CloakName(g.Key)} {g.Count():N0}");
            if (events.Count > 0)
                sb.AppendLine("By cloak: " + string.Join(", ", byCloak));
            var users = CloakStore.GetTopUsernames(since, 5);
            if (users.Count > 0)
                sb.AppendLine("Top user names: " + string.Join(", ", users.Select(u => $"{u.User}{(u.RealAccount ? " (real)" : "")} {u.Attempts:N0}")));
            var countries = events.Select(x => GeoIp.Lookup(x.Ip) ?? "").GroupBy(x => x).OrderByDescending(g => g.Count()).Take(5)
                .Select(g => $"{GeoIp.CountryName(g.Key)} {g.Count():N0}");
            if (events.Count > 0)
                sb.AppendLine("Top countries: " + string.Join(", ", countries));
            await Alert(AlertKind.DailySummary, "Daily summary", sb.ToString().TrimEnd());
        }
        catch (Exception ex) { logger.LogWarning(ex, "Daily summary failed."); }
    }

    private async Task HourlyAsync(CancellationToken ct)
    {
        var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        do
        {
            try { CloakStore.TrimLogs(); }
            catch (Exception ex) { logger.LogWarning(ex, "Trimming logs failed."); }

            bool rangesChanged = false;
            try
            {
                if (GeoIp.IsStale())
                {
                    var count = await GeoIp.UpdateAsync(ct);
                    logger.LogInformation("Country database updated: {Count} ranges.", count);
                    rangesChanged = CloakStore.GetCountryMode() != CountryMode.Off;
                }
            }
            catch (OperationCanceledException) { return; }
            catch (Exception ex) { logger.LogWarning(ex, "Country database update failed; will retry later."); }

            try
            {
                if (BlockFeeds.IsStale())
                {
                    var summary = await BlockFeeds.UpdateAllAsync(ct);
                    logger.LogInformation("Block lists: {Summary}.", summary);
                    rangesChanged = true;
                }
            }
            catch (OperationCanceledException) { return; }
            catch (Exception ex) { logger.LogWarning(ex, "Block list update failed; will retry later."); }

            if (rangesChanged)
                SyncRanges();
        }
        while (await timer.WaitForNextTickAsync(ct));
    }

    private static readonly Dictionary<CloakEnum, string> Names = [];

    private static string CloakName(CloakEnum id)
    {
        lock (Names)
        {
            if (Names.Count == 0)
                foreach (var c in CloakStore.GetCloaks())
                    Names[c.Id] = c.Name;
            return Names.TryGetValue(id, out var n) ? n : id.ToString();
        }
    }

    private async Task Alert(AlertKind kind, string title, string text)
    {
        try { await Alerter.SendAsync(kind, title, text, _stopping); }
        catch (Exception ex) { logger.LogWarning(ex, "Alert '{Title}' failed.", title); }
    }

    private void SyncIps()
    {
        lock (_blockLock)
        {
            try { BlockEngine.SyncIps(); }
            catch (Exception ex) { logger.LogError(ex, "Updating firewall block rules failed."); }
        }
    }

    private void SyncRanges()
    {
        try
        {
            var r = BlockEngine.SyncRanges();
            if (r.Entries > 0)
                logger.LogInformation("Country and block list rules: {Entries} ranges ({Countries} country, {Feeds} block list).", r.Entries, r.CountryRanges, r.FeedRanges);
        }
        catch (Exception ex) { logger.LogError(ex, "Updating country and block list rules failed."); }
    }
}

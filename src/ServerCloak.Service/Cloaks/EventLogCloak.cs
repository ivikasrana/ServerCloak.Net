using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Text.RegularExpressions;
using ServerCloak.Core;

namespace ServerCloak.Service.Cloaks;

/// <summary>Watches one event log for new records and extracts the attacker IP (and user name) from each.</summary>
public class EventLogCloak(CloakSetting setting, ILogger logger, string logName, string xpath, Func<EventRecord, IEnumerable<Hit>> extract)
    : Cloak(setting, logger)
{
    private EventLogWatcher? _watcher;

    public override void Start()
    {
        if (!OsInfo.LogExists(logName))
        {
            Logger.LogInformation("{Cloak}: event log '{Log}' is not present on this server, cloak skipped.", Setting.Name, logName);
            return;
        }
        _watcher = new EventLogWatcher(new EventLogQuery(logName, PathType.LogName, xpath));
        _watcher.EventRecordWritten += OnEventRecordWritten;
        _watcher.Enabled = true;
        Active = true;
        Logger.LogInformation("{Cloak} is watching '{Log}'.", Setting.Name, logName);
    }

    public override void Stop()
    {
        if (_watcher == null)
            return;
        _watcher.Enabled = false;
        _watcher.EventRecordWritten -= OnEventRecordWritten;
        _watcher.Dispose();
        _watcher = null;
        Active = false;
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord == null)
            return;
        try
        {
            using var record = e.EventRecord;
            foreach (var hit in extract(record).DistinctBy(x => x.Ip))
                Raise(hit, record.Id, $"{Setting.Name} (event {record.Id})" + (hit.User != null ? $", user {hit.User}" : ""), record.TimeCreated);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "{Cloak}: reading event failed.", Setting.Name);
        }
    }

    // Extractors

    public static string? Data(EventRecord record, string name)
    {
        if (record is not EventLogRecord r)
            return null;
        var values = r.GetPropertyValues(new EventLogPropertySelector([$"Event/EventData/Data[@Name='{name}']"]));
        if (values.Count > 0 && values[0] != null)
            return values[0]?.ToString();
        // Some logs (RD Gateway) use UserData instead of EventData.
        values = r.GetPropertyValues(new EventLogPropertySelector([$"Event/UserData/*/{name}"]));
        return values.Count > 0 ? values[0]?.ToString() : null;
    }

    private static string AllText(EventRecord record) => string.Join(" ", record.Properties.Select(p => Convert.ToString(p.Value)));

    /// <summary>4771: Kerberos failure code 0x18 (wrong password) means the account exists.</summary>
    public static IEnumerable<Hit> Kerberos(EventRecord record)
    {
        yield return new Hit(Data(record, "IpAddress"), LogParsers.Clean(Data(record, "TargetUserName")), LogParsers.IsRealAccountStatus(Data(record, "Status")));
    }

    /// <summary>4625: the reason is in SubStatus when Status is the generic 0xC000006D.</summary>
    public static IEnumerable<Hit> Logon4625(EventRecord record)
    {
        var status = Data(record, "SubStatus");
        if (string.IsNullOrEmpty(status) || status == "0x0")
            status = Data(record, "Status");
        yield return new Hit(Data(record, "IpAddress"), LogParsers.Clean(Data(record, "TargetUserName")), LogParsers.IsRealAccountStatus(status));
    }

    public static IEnumerable<Hit> NamedData(EventRecord record, string name)
    {
        yield return new Hit(Data(record, name));
    }

    /// <summary>First IP found in any event property (FileMaker, RRAS put the IP in message text).</summary>
    public static IEnumerable<Hit> AnyIp(EventRecord record)
    {
        foreach (var p in record.Properties)
            if (IpUtil.FindIp(Convert.ToString(p.Value)) is { } ip)
            {
                yield return new Hit(ip);
                yield break;
            }
    }

    public static IEnumerable<Hit> Sql(EventRecord record)
    {
        yield return LogParsers.ParseSql(AllText(record));
    }

    /// <summary>RD Gateway: IpAddress and Username in UserData, with a fallback to any IP in the event.</summary>
    public static IEnumerable<Hit> Gateway(EventRecord record)
    {
        var ip = Data(record, "IpAddress") ?? IpUtil.FindIp(AllText(record));
        var user = Data(record, "Username");
        int slash = user?.LastIndexOf('\\') ?? -1;
        yield return new Hit(ip, LogParsers.Clean(slash >= 0 ? user![(slash + 1)..] : user));
    }

    /// <summary>Event 4776 only has a workstation name, so it is resolved through DNS.</summary>
    public static IEnumerable<Hit> ResolveWorkstation(EventRecord record)
    {
        var host = Data(record, "Workstation")?.Trim().TrimStart('\\');
        if (string.IsNullOrEmpty(host) || host == "-")
            yield break;
        var user = LogParsers.Clean(Data(record, "TargetUserName"));
        bool real = LogParsers.IsRealAccountStatus(Data(record, "Status"));
        if (IpUtil.Normalize(host) is { } direct)
        {
            yield return new Hit(direct, user, real);
            yield break;
        }
        IPAddress[] addresses;
        try { addresses = Dns.GetHostAddresses(host); }
        catch { yield break; }
        foreach (var a in addresses)
            yield return new Hit(a.ToString(), user, real);
    }

    /// <summary>OpenSSH writes the sshd message into a single "payload" field.</summary>
    public static IEnumerable<Hit> OpenSshFailure(EventRecord record)
    {
        var payload = Data(record, "payload") ?? AllText(record);
        if (LogParsers.ParseSsh(payload) is { } hit)
            yield return hit;
    }

    /// <summary>Custom rule: regex on the event text when a pattern is set, otherwise the first IP in the event.</summary>
    public static Func<EventRecord, IEnumerable<Hit>> Custom(Regex? pattern) => record => CustomHits(record, pattern);

    private static IEnumerable<Hit> CustomHits(EventRecord record, Regex? pattern)
    {
        if (pattern == null)
            return AnyIp(record);
        string text;
        try { text = record.FormatDescription() ?? AllText(record); }
        catch { text = AllText(record); }
        var hit = LogParsers.ParseCustom(pattern, text) ?? LogParsers.ParseCustom(pattern, AllText(record));
        return hit == null ? [] : [hit];
    }

    public static string XPathForIds(string? ids)
    {
        var list = (ids ?? "").Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries)
            .Select(x => int.TryParse(x, out var n) ? n : -1).Where(n => n >= 0).Distinct().ToList();
        return list.Count == 0 ? "*" : $"*[System[{string.Join(" or ", list.Select(n => $"EventID={n}"))}]]";
    }
}

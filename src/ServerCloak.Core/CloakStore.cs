using System.Globalization;
using System.Net;
using Microsoft.EntityFrameworkCore;

namespace ServerCloak.Core;

/// <summary>All database work for the service and the UI. Each call uses its own short-lived context.</summary>
public static class CloakStore
{
    public const string KeyTheme = "Theme";
    public const string KeyGeoUpdated = "GeoUpdated";
    public const string KeyGeoSource = "GeoSource";
    public const string KeyUseDynamicKeywords = "UseDynamicKeywords";
    public const string KeyDynamicKeywordId = "DynamicKeywordId";
    public const string KeyEscalation = "Escalation";
    public const string KeyEscalationSteps = "EscalationSteps";
    public const string KeyDryRun = "DryRun";
    public const string KeyHealthHours = "HealthHours";
    public const string KeyLogRetentionDays = "LogRetentionDays";
    public const string KeyCountryMode = "CountryMode";
    public const string KeyFeedHours = "FeedHours";
    public const string KeyAbuseIpDbKey = "AbuseIpDbKey";
    public const string KeyAbuseIpDbReport = "AbuseIpDbReport";
    public const string KeyCleanShutdown = "CleanShutdown";
    public const string KeyRangesChanged = "RangesChanged";
    public const string KeyUpdateRepo = "UpdateRepo";
    public const string KeyUpdateChecked = "UpdateChecked";
    public const string KeyTrayEnabled = "TrayEnabled";
    public const string KeyTrayPopups = "TrayPopups";

    public const string DefaultEscalationSteps = "1h, 1d, permanent";
    public const int CustomIdStart = (int)CloakEnum.CustomBase;

    private static readonly object WriteLock = new();

    public static void Initialize()
    {
        AppPaths.EnsureDataDir();
        using (var db = new CloakDb())
        {
            SchemaUpgrade.Apply(db);
            var existing = db.Cloaks.Select(x => x.Id).ToHashSet();
            foreach (var d in DefaultCloaks().Where(d => !existing.Contains(d.Id)))
                db.Cloaks.Add(d);
            var feedUrls = db.Feeds.Select(x => x.Url).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var f in BlockFeeds.Defaults().Where(f => !feedUrls.Contains(f.Url)))
                db.Feeds.Add(f);
            db.SaveChanges();
        }
        using (var logs = new LogDb())
            SchemaUpgrade.Apply(logs);
    }

    public static IEnumerable<CloakSetting> DefaultCloaks()
    {
        var iisLogs = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\", @"inetpub\logs\LogFiles");
        CloakSetting C(CloakEnum id, string name, string desc, CloakKind kind, bool enabled = true, int port = 0, string? logPath = null)
            => new() { Id = id, Name = name, Description = desc, Kind = kind, Enabled = enabled, Port = port, LogPath = logPath };

        yield return C(CloakEnum.WindowsLogon, "Windows logon", "Failed logons with source IP (Security 4625): RDP with NLA, SMB, WinRM, Hyper-V remote management, IIS Windows auth", CloakKind.EventLog);
        yield return C(CloakEnum.WindowsSecurity, "Remote Desktop", "RDP failed logins (RdpCoreTS 140)", CloakKind.EventLog);
        yield return C(CloakEnum.RdGateway, "RD Gateway", "Remote Desktop Gateway connection authorization failures (TerminalServices-Gateway 201, 301)", CloakKind.EventLog);
        yield return C(CloakEnum.ActiveDirectory, "Active Directory", "NTLM credential validation failures (Security 4776)", CloakKind.EventLog);
        yield return C(CloakEnum.Kerberos, "Kerberos", "Kerberos pre-authentication failures (Security 4771)", CloakKind.EventLog);
        yield return C(CloakEnum.Sql, "SQL Server", "SQL Server failed logins (Application 18456)", CloakKind.EventLog);
        yield return C(CloakEnum.OpenSsh, "OpenSSH", "OpenSSH Server failed passwords and invalid users (OpenSSH/Operational)", CloakKind.EventLog);
        yield return C(CloakEnum.RoutingAndRemoteAccess, "RRAS / VPN", "Routing and Remote Access rejected connections (System 20271)", CloakKind.EventLog);
        yield return C(CloakEnum.FileMaker, "FileMaker", "FileMaker Server failed logins (Application 661)", CloakKind.EventLog);
        yield return C(CloakEnum.IisWeb, "IIS web", "IIS log 401.1 (invalid credentials)", CloakKind.LogFile, logPath: Path.Combine(iisLogs, "W3SVC*"));
        yield return C(CloakEnum.Exchange, "Exchange / OWA", "IIS log 401 on OWA, ECP, EWS, ActiveSync, MAPI, RPC, Autodiscover and OAB (turn off IIS web on Exchange servers to avoid double counting)", CloakKind.LogFile, enabled: false, logPath: Path.Combine(iisLogs, "W3SVC*"));
        yield return C(CloakEnum.RdWeb, "RD Web Access", "IIS log: failed sign-in posts to /RDWeb login.aspx", CloakKind.LogFile, logPath: Path.Combine(iisLogs, "W3SVC*"));
        yield return C(CloakEnum.IisFtp, "IIS FTP", "IIS FTP log PASS with 530 reply, works with FTPS", CloakKind.LogFile, logPath: Path.Combine(iisLogs, "FTPSVC*"));
        yield return C(CloakEnum.IisSmtp, "IIS SMTP", "IIS SMTP log 535 replies", CloakKind.LogFile, logPath: Path.Combine(Environment.SystemDirectory, @"LogFiles\SmtpSvc*"));
        yield return C(CloakEnum.Smtp, "SMTP sniffer", "Packet sniffer for 535/504 replies on plain-text SMTP (IPv4 and IPv6)", CloakKind.PacketSniffer, port: 25);
        yield return C(CloakEnum.Ftp, "FTP sniffer", "Packet sniffer for 530 replies on plain-text FTP (IPv4 and IPv6)", CloakKind.PacketSniffer, enabled: false, port: 21);
        yield return C(CloakEnum.Rdp, "RDP sniffer", "Packet sniffer for TLS alerts on the RDP port (legacy, can count normal disconnects)", CloakKind.PacketSniffer, enabled: false, port: 3389);
    }

    // Cloaks

    public static List<CloakSetting> GetCloaks()
    {
        using var db = new CloakDb();
        return db.Cloaks.AsNoTracking().ToList().OrderBy(x => x.IsCustom).ThenBy(x => x.Kind).ThenBy(x => (int)x.Id).ToList();
    }

    public static void SaveCloaks(IEnumerable<CloakSetting> cloaks)
    {
        lock (WriteLock)
        {
            using var db = new CloakDb();
            foreach (var c in cloaks)
            {
                var row = db.Cloaks.Find(c.Id);
                if (row == null)
                    continue;
                row.Enabled = c.Enabled;
                row.Port = c.Port;
                row.Limit = Math.Max(1, c.Limit);
                row.BlockDuration = c.BlockDuration;
                row.LogPath = c.LogPath;
            }
            db.SaveChanges();
        }
    }

    /// <summary>Adds or updates a custom rule. A new rule gets the next free id from 10000.</summary>
    public static CloakSetting SaveCustomCloak(CloakSetting c)
    {
        lock (WriteLock)
        {
            using var db = new CloakDb();
            CloakSetting? row = c.Id >= CloakEnum.CustomBase ? db.Cloaks.Find(c.Id) : null;
            if (row == null)
            {
                int next = Math.Max(CustomIdStart, db.Cloaks.Select(x => (int)x.Id).AsEnumerable().DefaultIfEmpty(0).Max() + 1);
                row = new CloakSetting { Id = (CloakEnum)next, IsCustom = true };
                db.Cloaks.Add(row);
            }
            row.Name = c.Name.Trim();
            row.Description = c.Kind == CloakKind.EventLog
                ? $"Custom: {c.EventLogName} event {c.EventIds}"
                : $"Custom: {c.FileFilter} in {c.LogPath}";
            row.Kind = c.Kind;
            row.Enabled = c.Enabled;
            row.Limit = Math.Max(1, c.Limit);
            row.BlockDuration = c.BlockDuration;
            row.LogPath = c.LogPath;
            row.EventLogName = c.EventLogName;
            row.EventIds = c.EventIds;
            row.Pattern = c.Pattern;
            row.FileFilter = c.FileFilter;
            db.SaveChanges();
            return row;
        }
    }

    public static void DeleteCustomCloak(CloakEnum id)
    {
        if (id < CloakEnum.CustomBase)
            return;
        lock (WriteLock)
        {
            using var db = new CloakDb();
            db.Cloaks.Where(x => x.Id == id).ExecuteDelete();
            db.IpLogs.Where(x => x.Cloak == id).ExecuteDelete();
        }
    }

    // Attacks and blocks

    public record AttackResult(bool Blocked, string Ip, DateTime? Expires, int Strikes, bool Ignored);

    /// <summary>Records one failed attempt and blocks the address when it reaches the cloak's limit.</summary>
    public static AttackResult RecordAttack(AttackDetectedEventArgs data)
    {
        var ip = IpUtil.Normalize(data.IpAddress);
        if (ip == null || IpUtil.IsLoopbackOrUnspecified(ip) || IsWhitelisted(ip))
            return new AttackResult(false, ip ?? data.IpAddress, null, 0, true);

        lock (WriteLock)
        {
            using var db = new CloakDb();
            var cloak = db.Cloaks.AsNoTracking().FirstOrDefault(x => x.Id == data.CloakName);
            var limit = cloak?.Limit ?? 5;
            var now = DateTime.Now;

            var row = db.IpLogs.FirstOrDefault(x => x.Ip == ip && x.Cloak == data.CloakName);
            if (row == null)
            {
                row = new IpLog { Ip = ip, Cloak = data.CloakName, Created = now, Country = GeoIp.Lookup(db, ip) };
                db.IpLogs.Add(row);
            }
            row.Attacks++;
            row.LastSeen = now;

            bool block = row.Locked == null && row.Attacks >= limit;
            int strikes = 0;
            if (block)
            {
                (row.Expires, strikes) = NextBlock(db, ip, cloak?.BlockDuration ?? BlockDurationEnum.Month3, now);
                row.Locked = now;
            }
            db.SaveChanges();

            using (var logs = new LogDb())
            {
                logs.AttackEvents.Add(new AttackEvent
                {
                    Ip = ip, Cloak = data.CloakName, EventId = data.EventId, Message = data.EventMessage,
                    Username = LogParsers.Clean(data.Username), RealAccount = data.RealAccount, Blocked = block,
                    Time = data.CreateDate == default ? now : data.CreateDate
                });
                logs.SaveChanges();
            }
            return new AttackResult(block, ip, row.Expires, strikes, false);
        }
    }

    /// <summary>Block length for this address: escalation steps when on, otherwise the cloak's duration.</summary>
    private static (DateTime? Expires, int Strikes) NextBlock(CloakDb db, string ip, BlockDurationEnum cloakDuration, DateTime now)
    {
        var offender = db.Offenders.Find(ip);
        if (offender == null)
        {
            offender = new Offender { Ip = ip };
            db.Offenders.Add(offender);
        }
        // Strikes are forgiven after a year without a block.
        if (offender.LastBlocked < now.AddYears(-1))
            offender.Strikes = 0;
        offender.Strikes++;
        offender.LastBlocked = now;

        if (GetBool(KeyEscalation, true))
        {
            var steps = ParseSteps(GetSetting(KeyEscalationSteps) ?? DefaultEscalationSteps);
            if (steps.Count > 0)
            {
                var step = steps[Math.Min(offender.Strikes, steps.Count) - 1];
                return (step == null ? null : now + step.Value, offender.Strikes);
            }
        }
        return (cloakDuration == BlockDurationEnum.Permanent ? null : now.AddDays((int)cloakDuration), offender.Strikes);
    }

    /// <summary>Parses "1h, 1d, 1w, permanent" into durations; null means permanent.</summary>
    public static List<TimeSpan?> ParseSteps(string text)
    {
        var list = new List<TimeSpan?>();
        foreach (var raw in text.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries))
        {
            var s = raw.Trim().ToLowerInvariant();
            if (s is "0" or "perm" or "permanent" or "forever")
            {
                list.Add(null);
                continue;
            }
            if (s.Length < 2 || !double.TryParse(s[..^1], NumberStyles.Float, CultureInfo.InvariantCulture, out var n) || n <= 0)
                throw new FormatException($"'{raw}' is not a valid step. Use m, h, d or w, for example 1h, 1d, 1w, permanent.");
            list.Add(s[^1] switch
            {
                'm' => TimeSpan.FromMinutes(n),
                'h' => TimeSpan.FromHours(n),
                'd' => TimeSpan.FromDays(n),
                'w' => TimeSpan.FromDays(n * 7),
                _ => throw new FormatException($"'{raw}' is not a valid step. Use m, h, d or w, for example 1h, 1d, 1w, permanent.")
            });
        }
        return list;
    }

    /// <summary>Blocks an address by hand. A null duration is permanent.</summary>
    public static void ManualBlock(string ipAddress, TimeSpan? duration)
    {
        var ip = IpUtil.Normalize(ipAddress) ?? throw new ArgumentException($"'{ipAddress}' is not a valid IP address.");
        lock (WriteLock)
        {
            using var db = new CloakDb();
            var now = DateTime.Now;
            var row = db.IpLogs.FirstOrDefault(x => x.Ip == ip && x.Cloak == CloakEnum.Manual);
            if (row == null)
            {
                row = new IpLog { Ip = ip, Cloak = CloakEnum.Manual, Created = now, Country = GeoIp.Lookup(db, ip) };
                db.IpLogs.Add(row);
            }
            row.LastSeen = now;
            row.Locked = now;
            row.Expires = duration == null ? null : now + duration;
            db.SaveChanges();
        }
    }

    public static List<string> GetBlockedIps()
    {
        using var db = new CloakDb();
        return db.IpLogs.Where(x => x.Locked != null).Select(x => x.Ip).Distinct().ToList();
    }

    public static int GetBlockedCount()
    {
        using var db = new CloakDb();
        return db.IpLogs.Where(x => x.Locked != null).Select(x => x.Ip).Distinct().Count();
    }

    public static void UnblockIp(string ipAddress)
    {
        var ip = IpUtil.Normalize(ipAddress) ?? ipAddress.Trim();
        lock (WriteLock)
        {
            using var db = new CloakDb();
            db.IpLogs.Where(x => x.Ip == ip && x.Cloak == CloakEnum.Manual).ExecuteDelete();
            foreach (var row in db.IpLogs.Where(x => x.Ip == ip))
            {
                row.Attacks = 0;
                row.Locked = null;
                row.Expires = null;
            }
            db.SaveChanges();
        }
    }

    /// <summary>Clears blocks whose time has passed and trims old history. Returns true if any block was removed.</summary>
    public static bool ExpireBlocks()
    {
        lock (WriteLock)
        {
            using var db = new CloakDb();
            var now = DateTime.Now;
            var expired = db.IpLogs.Where(x => x.Locked != null && x.Expires != null && x.Expires < now).ToList();
            foreach (var row in expired)
            {
                row.Locked = null;
                row.Expires = null;
                row.Attacks = 0;
            }
            db.SaveChanges();
            return expired.Count > 0;
        }
    }

    public static void TrimLogs()
    {
        int days = Math.Max(7, GetInt(KeyLogRetentionDays, 180));
        var cutoff = DateTime.Now.AddDays(-days);
        using var logs = new LogDb();
        logs.AttackEvents.Where(x => x.Time < cutoff).ExecuteDelete();
        logs.Notifications.Where(x => x.Time < DateTime.Now.AddDays(-30)).ExecuteDelete();
    }

    public static void ClearLogs()
    {
        using var logs = new LogDb();
        logs.AttackEvents.ExecuteDelete();
        logs.Notifications.ExecuteDelete();
        logs.Database.ExecuteSqlRaw("VACUUM;");
    }

    // Queries

    public record IpPage(List<IpLog> Rows, int Total);

    public static IpPage GetIpLogs(CloakEnum? cloak, bool blockedOnly, string? search, int skip, int take)
    {
        using var db = new CloakDb();
        var q = db.IpLogs.AsNoTracking();
        if (cloak != null)
            q = q.Where(x => x.Cloak == cloak);
        if (blockedOnly)
            q = q.Where(x => x.Locked != null);
        search = search?.Trim();
        if (!string.IsNullOrEmpty(search))
        {
            var codes = GeoIp.CountryCodesMatching(search);
            var cloakIds = db.Cloaks.AsNoTracking().ToList()
                .Where(x => x.Name.Contains(search, StringComparison.OrdinalIgnoreCase)).Select(x => x.Id).ToList();
            if ("manual".Contains(search, StringComparison.OrdinalIgnoreCase))
                cloakIds.Add(CloakEnum.Manual);
            q = q.Where(x => x.Ip.Contains(search) || (x.Country != null && codes.Contains(x.Country)) || cloakIds.Contains(x.Cloak));
        }
        int total = q.Count();
        var rows = q.OrderByDescending(x => x.LastSeen).Skip(skip).Take(take).ToList();
        return new IpPage(rows, total);
    }

    public static List<AttackEvent> GetRecentEvents(int count)
    {
        using var logs = new LogDb();
        return logs.AttackEvents.AsNoTracking().OrderByDescending(x => x.Id).Take(count).ToList();
    }

    public static List<AttackEvent> GetEvents(DateTime since)
    {
        using var logs = new LogDb();
        return logs.AttackEvents.AsNoTracking().Where(x => x.Time >= since).OrderBy(x => x.Time).ToList();
    }

    public static DateTime? GetLastEventTime()
    {
        using var logs = new LogDb();
        return logs.AttackEvents.OrderByDescending(x => x.Id).Select(x => (DateTime?)x.Time).FirstOrDefault();
    }

    public record CloakStats(CloakEnum Cloak, int Attacks, int Blocked);
    public record CountryStats(string Country, int Ips, int Attacks, int Blocked);
    public record UserStats(string User, int Attempts, int Ips, bool RealAccount, DateTime LastSeen);
    public record TimelinePoint(DateTime Start, int Attempts, int Blocks);

    public static List<CloakStats> GetCloakStats()
    {
        using var db = new CloakDb();
        return db.IpLogs.GroupBy(x => x.Cloak)
            .Select(g => new CloakStats(g.Key, g.Sum(x => x.Attacks), g.Count(x => x.Locked != null)))
            .ToList();
    }

    public static List<CountryStats> GetCountryStats()
    {
        using var db = new CloakDb();
        return db.IpLogs.GroupBy(x => x.Country ?? "")
            .Select(g => new CountryStats(g.Key, g.Select(x => x.Ip).Distinct().Count(), g.Sum(x => x.Attacks), g.Count(x => x.Locked != null)))
            .ToList()
            .OrderByDescending(x => x.Attacks)
            .ToList();
    }

    public static int GetAttacksSince(DateTime since)
    {
        using var logs = new LogDb();
        return logs.AttackEvents.Count(x => x.Time >= since);
    }

    public static int GetBlocksSince(DateTime since)
    {
        using var logs = new LogDb();
        return logs.AttackEvents.Count(x => x.Blocked && x.Time >= since);
    }

    public static int GetTotalEvents()
    {
        using var logs = new LogDb();
        return logs.AttackEvents.Count();
    }

    public static List<UserStats> GetTopUsernames(DateTime since, int count)
    {
        using var logs = new LogDb();
        return logs.AttackEvents.AsNoTracking()
            .Where(x => x.Time >= since && x.Username != null)
            .GroupBy(x => x.Username!)
            .Select(g => new UserStats(g.Key, g.Count(), g.Select(x => x.Ip).Distinct().Count(), g.Any(x => x.RealAccount), g.Max(x => x.Time)))
            .ToList()
            .OrderByDescending(x => x.RealAccount)
            .ThenByDescending(x => x.Attempts)
            .Take(count)
            .ToList();
    }

    /// <summary>Attempts and blocks per bucket from <paramref name="from"/> to now.</summary>
    public static List<TimelinePoint> GetTimeline(DateTime from, TimeSpan bucket)
    {
        using var logs = new LogDb();
        var times = logs.AttackEvents.AsNoTracking().Where(x => x.Time >= from).Select(x => new { x.Time, x.Blocked }).ToList();
        int n = (int)Math.Ceiling((DateTime.Now - from) / bucket);
        var points = Enumerable.Range(0, Math.Max(1, n)).Select(i => new int[2]).ToArray();
        foreach (var t in times)
        {
            int i = Math.Clamp((int)((t.Time - from) / bucket), 0, points.Length - 1);
            points[i][0]++;
            if (t.Blocked)
                points[i][1]++;
        }
        return points.Select((p, i) => new TimelinePoint(from + bucket * i, p[0], p[1])).ToList();
    }

    // Notifications

    public static void AddNotification(NotificationLevel level, string title, string text)
    {
        try
        {
            using var logs = new LogDb();
            logs.Notifications.Add(new Notification { Time = DateTime.Now, Level = level, Title = title, Text = text });
            logs.SaveChanges();
        }
        catch (Exception ex)
        {
            AppPaths.LogError("Add notification", ex);
        }
    }

    public static List<Notification> GetNotificationsAfter(long id)
    {
        using var logs = new LogDb();
        return logs.Notifications.AsNoTracking().Where(x => x.Id > id).OrderBy(x => x.Id).Take(50).ToList();
    }

    public static long GetLastNotificationId()
    {
        using var logs = new LogDb();
        return logs.Notifications.Select(x => (long?)x.Id).Max() ?? 0;
    }

    // Whitelist

    private static List<string>? _whitelistCache;
    private static DateTime _whitelistCacheTime;

    public static List<string> GetWhitelist()
    {
        using var db = new CloakDb();
        return db.Whitelist.AsNoTracking().OrderBy(x => x.Id).Select(x => x.Value).ToList();
    }

    public static void SaveWhitelist(IEnumerable<string> entries)
    {
        lock (WriteLock)
        {
            using var db = new CloakDb();
            db.Whitelist.ExecuteDelete();
            db.Whitelist.AddRange(entries.Select(x => x.Trim()).Where(x => x.Length > 0).Distinct().Select(x => new WhitelistEntry { Value = x }));
            db.SaveChanges();
            _whitelistCache = null;
        }
    }

    public static void AddToWhitelist(string entry, string? note = null)
    {
        var list = GetWhitelist();
        if (list.Any(x => x.Equals(entry, StringComparison.OrdinalIgnoreCase)))
            return;
        if (!string.IsNullOrEmpty(note))
            list.Add($"# {note}");
        list.Add(entry);
        SaveWhitelist(list);
    }

    /// <summary>Whitelist, this server's own addresses and signed-in Remote Desktop clients.</summary>
    public static bool IsWhitelisted(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address))
            return false;
        if (IpUtil.LocalAddresses.Any(x => x.Equals(address)) || SessionGuard.IsProtected(address))
            return true;
        if (_whitelistCache == null || DateTime.Now - _whitelistCacheTime > TimeSpan.FromMinutes(1))
        {
            _whitelistCache = GetWhitelist();
            _whitelistCacheTime = DateTime.Now;
        }
        return _whitelistCache.Any(x => IpUtil.Matches(x, address));
    }

    /// <summary>Everything that country and block list rules must never cover.</summary>
    public static RangeSet GetNeverBlock()
    {
        var set = new RangeSet();
        set.AddRange(RangeSet.Reserved);
        set.AddRange(GetWhitelist().Where(x => !x.TrimStart().StartsWith('#')));
        foreach (var a in IpUtil.LocalAddresses.Concat(SessionGuard.SessionAddresses))
            set.Add(a.ToString());
        return set;
    }

    // Country rules

    public static CountryMode GetCountryMode() => Enum.TryParse<CountryMode>(GetSetting(KeyCountryMode), out var m) ? m : CountryMode.Off;

    public static List<string> GetCountryRules()
    {
        using var db = new CloakDb();
        return db.CountryRules.AsNoTracking().Select(x => x.Code).OrderBy(x => x).ToList();
    }

    public static void SaveCountryRules(CountryMode mode, IEnumerable<string> codes)
    {
        lock (WriteLock)
        {
            using var db = new CloakDb();
            db.CountryRules.ExecuteDelete();
            db.CountryRules.AddRange(codes.Select(x => x.Trim().ToUpperInvariant()).Where(x => x.Length == 2).Distinct().Select(x => new CountryRule { Code = x }));
            db.SaveChanges();
        }
        SetSetting(KeyCountryMode, mode.ToString());
    }

    // Block list feeds

    public static List<FeedSource> GetFeeds()
    {
        using var db = new CloakDb();
        return db.Feeds.AsNoTracking().OrderBy(x => x.Id).ToList();
    }

    public static void SaveFeeds(IEnumerable<FeedSource> feeds)
    {
        lock (WriteLock)
        {
            using var db = new CloakDb();
            var keep = new HashSet<int>();
            foreach (var f in feeds)
            {
                var row = f.Id > 0 ? db.Feeds.Find(f.Id) : null;
                if (row == null)
                {
                    row = new FeedSource { Name = f.Name, Url = f.Url, Format = f.Format };
                    db.Feeds.Add(row);
                }
                row.Name = f.Name;
                row.Url = f.Url;
                row.Format = f.Format;
                row.Enabled = f.Enabled;
                db.SaveChanges();
                keep.Add(row.Id);
            }
            var removed = db.Feeds.Where(x => !keep.Contains(x.Id)).Select(x => x.Id).ToList();
            db.FeedEntries.Where(x => removed.Contains(x.SourceId)).ExecuteDelete();
            db.Feeds.Where(x => removed.Contains(x.Id)).ExecuteDelete();
        }
    }

    // Settings

    public static string? GetSetting(string key)
    {
        using var db = new CloakDb();
        return db.Settings.AsNoTracking().Where(x => x.Key == key).Select(x => x.Value).FirstOrDefault();
    }

    public static void SetSetting(string key, string value)
    {
        lock (WriteLock)
        {
            using var db = new CloakDb();
            var row = db.Settings.Find(key);
            if (row == null)
                db.Settings.Add(new Setting { Key = key, Value = value });
            else
                row.Value = value;
            db.SaveChanges();
        }
    }

    public static Dictionary<string, string> GetAllSettings()
    {
        using var db = new CloakDb();
        return db.Settings.AsNoTracking().ToDictionary(x => x.Key, x => x.Value);
    }

    public static bool GetBool(string key, bool fallback) => GetSetting(key) switch
    {
        "true" => true,
        "false" => false,
        _ => fallback
    };

    public static void SetBool(string key, bool value) => SetSetting(key, value ? "true" : "false");

    public static int GetInt(string key, int fallback)
        => int.TryParse(GetSetting(key), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : fallback;

    public static void SetInt(string key, int value) => SetSetting(key, value.ToString(CultureInfo.InvariantCulture));

    public static string GetSecret(string key) => Secret.Unprotect(GetSetting(key));

    public static void SetSecret(string key, string value) => SetSetting(key, Secret.Protect(value));
}

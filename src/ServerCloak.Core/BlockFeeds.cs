using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;

namespace ServerCloak.Core;

/// <summary>Shared block lists (Spamhaus DROP, FireHOL, AbuseIPDB) and reporting attackers to AbuseIPDB.</summary>
public static partial class BlockFeeds
{
    public const string AbuseIpDbBlacklistUrl = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=10000&plaintext";
    private const string AbuseIpDbReportUrl = "https://api.abuseipdb.com/api/v2/report";

    [GeneratedRegex("\"cidr\"\\s*:\\s*\"(?<v>[^\"]+)\"")]
    private static partial Regex JsonCidr();

    public static IEnumerable<FeedSource> Defaults()
    {
        yield return new FeedSource { Name = "Spamhaus DROP (IPv4)", Url = "https://www.spamhaus.org/drop/drop_v4.json", Format = FeedFormat.Text };
        yield return new FeedSource { Name = "Spamhaus DROP (IPv6)", Url = "https://www.spamhaus.org/drop/drop_v6.json", Format = FeedFormat.Text };
        yield return new FeedSource { Name = "FireHOL level 1", Url = "https://iplists.firehol.org/files/firehol_level1.netset", Format = FeedFormat.Text };
        yield return new FeedSource { Name = "AbuseIPDB blacklist (API key)", Url = AbuseIpDbBlacklistUrl, Format = FeedFormat.AbuseIpDb };
    }

    private static HttpClient NewClient()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"ServerCloak/{AppPaths.Version}");
        return http;
    }

    /// <summary>Parses a block list: one IP, range or CIDR per line, Spamhaus JSON lines, # and ; comments.</summary>
    public static List<string> Parse(string text)
    {
        var list = new List<string>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or ';')
                continue;
            if (line[0] == '{')
            {
                if (JsonCidr().Match(line) is { Success: true } m)
                    line = m.Groups["v"].Value;
                else
                    continue;
            }
            int cut = line.IndexOfAny([' ', '\t', ';', '#', ',']);
            if (cut > 0)
                line = line[..cut];
            if (RangeSet.TryParse(line, out _, out _))
                list.Add(line);
        }
        return list;
    }

    /// <summary>Downloads every enabled feed. Returns a short summary; errors are stored per feed.</summary>
    public static async Task<string> UpdateAllAsync(CancellationToken ct = default)
    {
        var feeds = CloakStore.GetFeeds().Where(x => x.Enabled).ToList();
        int ok = 0, failed = 0;
        using var http = NewClient();
        foreach (var feed in feeds)
        {
            string? error = null;
            List<string> entries = [];
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, feed.Url);
                if (feed.Format == FeedFormat.AbuseIpDb)
                {
                    var key = CloakStore.GetSecret(CloakStore.KeyAbuseIpDbKey);
                    if (key.Length == 0)
                        throw new InvalidOperationException("No AbuseIPDB API key is set.");
                    req.Headers.Add("Key", key);
                    req.Headers.Add("Accept", "text/plain");
                }
                using var resp = await http.SendAsync(req, ct);
                resp.EnsureSuccessStatusCode();
                entries = Parse(await resp.Content.ReadAsStringAsync(ct));
                if (entries.Count == 0)
                    throw new InvalidOperationException("The list was empty or not in a known format.");
                ok++;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                error = ex.Message;
                failed++;
            }
            Store(feed.Id, entries, error);
        }
        return $"{ok} block lists updated" + (failed > 0 ? $", {failed} failed" : "");
    }

    private static void Store(int sourceId, List<string> entries, string? error)
    {
        using var db = new CloakDb();
        var feed = db.Feeds.Find(sourceId);
        if (feed == null)
            return;
        if (error == null)
        {
            using var tx = db.Database.BeginTransaction();
            db.FeedEntries.Where(x => x.SourceId == sourceId).ExecuteDelete();
            db.FeedEntries.AddRange(entries.Distinct().Select(x => new FeedEntry { SourceId = sourceId, Value = x }));
            feed.Count = entries.Count;
            feed.Updated = DateTime.Now;
            feed.LastError = null;
            db.SaveChanges();
            tx.Commit();
        }
        else
        {
            feed.LastError = error;
            db.SaveChanges();
        }
    }

    public static bool IsStale()
    {
        int hours = Math.Max(1, CloakStore.GetInt(CloakStore.KeyFeedHours, 12));
        return CloakStore.GetFeeds().Any(x => x.Enabled && (x.Updated == null || DateTime.Now - x.Updated > TimeSpan.FromHours(hours)));
    }

    /// <summary>Entries from enabled feeds.</summary>
    public static List<string> EnabledEntries()
    {
        using var db = new CloakDb();
        var ids = db.Feeds.Where(x => x.Enabled).Select(x => x.Id).ToList();
        return db.FeedEntries.AsNoTracking().Where(x => ids.Contains(x.SourceId)).Select(x => x.Value).ToList();
    }

    // AbuseIPDB reporting

    private static readonly Dictionary<string, DateTime> LastReported = new();

    /// <summary>AbuseIPDB categories: 18 brute force, plus 22 SSH, 21 web app attack, 5 FTP brute force, 11 email.</summary>
    public static string Categories(CloakEnum cloak) => cloak switch
    {
        CloakEnum.OpenSsh => "18,22",
        CloakEnum.IisWeb or CloakEnum.Exchange or CloakEnum.RdWeb => "18,21",
        CloakEnum.IisFtp or CloakEnum.Ftp => "18,5",
        CloakEnum.IisSmtp or CloakEnum.Smtp => "18,11",
        _ => "18"
    };

    /// <summary>Reports a blocked address. Each address is reported at most once every 15 minutes, as AbuseIPDB requires.</summary>
    public static async Task<bool> ReportAsync(string ip, CloakEnum cloak, string cloakName, int attempts, CancellationToken ct = default)
    {
        if (!CloakStore.GetBool(CloakStore.KeyAbuseIpDbReport, false))
            return false;
        var key = CloakStore.GetSecret(CloakStore.KeyAbuseIpDbKey);
        if (key.Length == 0)
            return false;
        lock (LastReported)
        {
            if (LastReported.TryGetValue(ip, out var last) && DateTime.Now - last < TimeSpan.FromMinutes(15))
                return false;
            LastReported[ip] = DateTime.Now;
        }

        using var http = NewClient();
        using var req = new HttpRequestMessage(HttpMethod.Post, AbuseIpDbReportUrl)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["ip"] = ip,
                ["categories"] = Categories(cloak),
                ["comment"] = $"ServerCloak: {attempts} failed {cloakName} logins",
                ["timestamp"] = DateTimeOffset.Now.ToString("o")
            })
        };
        req.Headers.Add("Key", key);
        req.Headers.Add("Accept", "application/json");
        using var resp = await http.SendAsync(req, ct);
        return resp.IsSuccessStatusCode;
    }

    /// <summary>Checks the API key with a lookup of a documentation address.</summary>
    public static async Task<string> TestKeyAsync(string key, CancellationToken ct = default)
    {
        using var http = NewClient();
        using var req = new HttpRequestMessage(HttpMethod.Get, "https://api.abuseipdb.com/api/v2/check?ipAddress=127.0.0.1");
        req.Headers.Add("Key", key);
        req.Headers.Add("Accept", "application/json");
        using var resp = await http.SendAsync(req, ct);
        if (resp.IsSuccessStatusCode)
            return "The AbuseIPDB key works.";
        var body = await resp.Content.ReadAsStringAsync(ct);
        return $"AbuseIPDB answered {(int)resp.StatusCode}: {body[..Math.Min(200, body.Length)]}";
    }
}

using System.Globalization;
using System.IO.Compression;
using System.Net;
using Microsoft.EntityFrameworkCore;

namespace ServerCloak.Core;

/// <summary>IP to country lookup using the free DB-IP Lite country database (IPv4 and IPv6, CC BY 4.0, updated monthly).</summary>
public static class GeoIp
{
    public const string Attribution = "IP geolocation by DB-IP (db-ip.com), CC BY 4.0";
    private const string UrlFormat = "https://download.db-ip.com/free/dbip-country-lite-{0:yyyy-MM}.csv.gz";

    public static bool IsStale()
    {
        var updated = CloakStore.GetSetting(CloakStore.KeyGeoUpdated);
        return !DateTime.TryParse(updated, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) || DateTime.Now - date > TimeSpan.FromDays(32);
    }

    /// <summary>Downloads the latest monthly file and replaces the GeoRanges table. Returns the number of ranges imported.</summary>
    public static async Task<int> UpdateAsync(CancellationToken ct = default)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("ServerCloak/3.0");

        byte[]? gz = null;
        string? source = null;
        foreach (var month in new[] { DateTime.UtcNow, DateTime.UtcNow.AddMonths(-1) })
        {
            var url = string.Format(CultureInfo.InvariantCulture, UrlFormat, month);
            using var resp = await http.GetAsync(url, ct);
            if (resp.IsSuccessStatusCode)
            {
                gz = await resp.Content.ReadAsByteArrayAsync(ct);
                source = url;
                break;
            }
        }
        if (gz == null)
            throw new InvalidOperationException("The DB-IP country file could not be downloaded.");

        int count = 0;
        using (var db = new CloakDb())
        {
            await db.Database.OpenConnectionAsync(ct);
            var conn = db.Database.GetDbConnection();
            using var tx = conn.BeginTransaction();
            using (var del = conn.CreateCommand())
            {
                del.Transaction = tx;
                del.CommandText = "DELETE FROM GeoRanges";
                del.ExecuteNonQuery();
            }

            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "INSERT INTO GeoRanges (StartIp, EndIp, Country) VALUES ($s, $e, $c)";
            var ps = cmd.CreateParameter(); ps.ParameterName = "$s"; cmd.Parameters.Add(ps);
            var pe = cmd.CreateParameter(); pe.ParameterName = "$e"; cmd.Parameters.Add(pe);
            var pc = cmd.CreateParameter(); pc.ParameterName = "$c"; cmd.Parameters.Add(pc);
            cmd.Prepare();

            using var reader = new StreamReader(new GZipStream(new MemoryStream(gz), CompressionMode.Decompress));
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                var parts = line.Split(',');
                if (parts.Length < 3 || !IPAddress.TryParse(parts[0], out var start) || !IPAddress.TryParse(parts[1], out var end))
                    continue;
                ps.Value = IpUtil.ToKey(start);
                pe.Value = IpUtil.ToKey(end);
                pc.Value = parts[2].Trim().Trim('"').ToUpperInvariant();
                cmd.ExecuteNonQuery();
                count++;
            }
            tx.Commit();
        }

        CloakStore.SetSetting(CloakStore.KeyGeoUpdated, DateTime.Now.ToString("o", CultureInfo.InvariantCulture));
        CloakStore.SetSetting(CloakStore.KeyGeoSource, source!);
        BackfillCountries();
        return count;
    }

    public static string? Lookup(string ip)
    {
        using var db = new CloakDb();
        return Lookup(db, ip);
    }

    public static string? Lookup(CloakDb db, string ip)
    {
        if (!IPAddress.TryParse(ip, out var address))
            return null;
        var key = IpUtil.ToKey(address);
        var conn = db.Database.GetDbConnection();
        bool opened = false;
        if (conn.State != System.Data.ConnectionState.Open)
        {
            conn.Open();
            opened = true;
        }
        try
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT EndIp, Country FROM GeoRanges WHERE StartIp <= $k ORDER BY StartIp DESC LIMIT 1";
            var p = cmd.CreateParameter(); p.ParameterName = "$k"; p.Value = key; cmd.Parameters.Add(p);
            using var r = cmd.ExecuteReader();
            if (r.Read() && IpUtil.Compare(key, (byte[])r[0]) <= 0)
                return r.GetString(1);
        }
        catch { }
        finally
        {
            if (opened)
                conn.Close();
        }
        return null;
    }

    public static void BackfillCountries()
    {
        using var db = new CloakDb();
        foreach (var row in db.IpLogs.Where(x => x.Country == null || x.Country == "").ToList())
            row.Country = Lookup(db, row.Ip);
        db.SaveChanges();
    }

    private static List<(string Code, string Name)>? _countries;

    /// <summary>All countries known to Windows, sorted by name.</summary>
    public static IReadOnlyList<(string Code, string Name)> AllCountries
    {
        get
        {
            if (_countries != null)
                return _countries;
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in CultureInfo.GetCultures(CultureTypes.SpecificCultures))
            {
                try
                {
                    var r = new RegionInfo(c.Name);
                    if (r.TwoLetterISORegionName.Length == 2 && char.IsLetter(r.TwoLetterISORegionName[0]))
                        map.TryAdd(r.TwoLetterISORegionName.ToUpperInvariant(), r.EnglishName);
                }
                catch { }
            }
            // Regions without a culture in Windows.
            foreach (var code in new[] { "AQ", "BV", "CC", "CX", "EH", "FK", "GS", "HM", "IO", "KP", "NF", "NR", "NU", "PN", "SH", "SJ", "TF", "TK", "UM", "VA", "WF", "XK" })
                if (!map.ContainsKey(code))
                    map[code] = CountryName(code);
            _countries = map.Select(x => (x.Key, x.Value)).OrderBy(x => x.Value).ToList();
            return _countries;
        }
    }

    /// <summary>Country codes whose code equals or whose name contains the text.</summary>
    public static List<string> CountryCodesMatching(string text)
    {
        text = text.Trim();
        if (text.Length == 0)
            return [];
        return AllCountries
            .Where(x => x.Code.Equals(text, StringComparison.OrdinalIgnoreCase) || (text.Length > 2 && x.Name.Contains(text, StringComparison.OrdinalIgnoreCase)))
            .Select(x => x.Code)
            .ToList();
    }

    public static int RangeCount()
    {
        using var db = new CloakDb();
        return db.GeoRanges.Count();
    }

    /// <summary>Address ranges for the given countries, or for every other country when <paramref name="invert"/> is set.</summary>
    public static RangeSet RangesFor(IReadOnlyCollection<string> codes, bool invert)
    {
        var set = new RangeSet();
        var wanted = codes.ToHashSet(StringComparer.OrdinalIgnoreCase);
        using var db = new CloakDb();
        db.Database.OpenConnection();
        var conn = db.Database.GetDbConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT StartIp, EndIp, Country FROM GeoRanges";
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var country = r.GetString(2);
            // ZZ is reserved or private space and is never blocked.
            if (country == "ZZ" || wanted.Contains(country) == invert)
                continue;
            set.Add((byte[])r[0], (byte[])r[1]);
        }
        return set;
    }

    public static string CountryName(string? code)
    {
        if (string.IsNullOrEmpty(code))
            return "Unknown";
        if (code == "ZZ")
            return "Reserved";
        try { return new RegionInfo(code).EnglishName; }
        catch { return code; }
    }
}

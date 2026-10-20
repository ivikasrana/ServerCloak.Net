using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace ServerCloak.Core;

public static partial class IpUtil
{
    [GeneratedRegex(@"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")]
    private static partial Regex V4Regex();

    [GeneratedRegex(@"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:(?<=:)(?:\d{1,3}\.){3}\d{1,3})?(?![0-9A-Fa-f:])")]
    private static partial Regex V6Regex();

    /// <summary>Parses an address and returns it in canonical form (IPv4-mapped IPv6 becomes IPv4).</summary>
    public static string? Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        value = value.Trim().Trim('[', ']');
        int scope = value.IndexOf('%');
        if (scope > 0)
            value = value[..scope];
        if (!IPAddress.TryParse(value, out var ip))
            return null;
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        return ip.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6 ? ip.ToString() : null;
    }

    /// <summary>Finds the first IPv4 or IPv6 address inside free text.</summary>
    public static string? FindIp(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return null;
        foreach (Match m in V4Regex().Matches(text))
            if (Normalize(m.Value) is { } v4)
                return v4;
        foreach (Match m in V6Regex().Matches(text))
            if (m.Value.Count(c => c == ':') >= 2 && Normalize(m.Value) is { } v6)
                return v6;
        return null;
    }

    public static bool IsLoopbackOrUnspecified(string ip)
        => !IPAddress.TryParse(ip, out var a) || IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any);

    /// <summary>16-byte big-endian key; IPv4 is stored as IPv4-mapped IPv6 so both families sort together.</summary>
    public static byte[] ToKey(IPAddress ip)
        => (ip.AddressFamily == AddressFamily.InterNetwork ? ip.MapToIPv6() : ip).GetAddressBytes();

    public static int Compare(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.SequenceCompareTo(b);

    /// <summary>Whitelist entry: single IP, CIDR (10.0.0.0/8) or range (10.0.0.1-10.0.0.50).</summary>
    public static bool Matches(string entry, IPAddress ip)
    {
        entry = entry.Trim();
        if (entry.Length == 0 || entry.StartsWith('#'))
            return false;
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();

        if (entry.Contains('/'))
            return RangeSet.TryParse(entry, out var netStart, out var netEnd)
                && RangeSet.FromAddress(ip) is var v && v >= netStart && v <= netEnd;

        int dash = entry.IndexOf('-');
        if (dash > 0)
        {
            if (!IPAddress.TryParse(entry[..dash].Trim(), out var start) || !IPAddress.TryParse(entry[(dash + 1)..].Trim(), out var end))
                return false;
            var key = ToKey(ip);
            return Compare(key, ToKey(start)) >= 0 && Compare(key, ToKey(end)) <= 0;
        }

        return IPAddress.TryParse(entry, out var single) && (single.IsIPv4MappedToIPv6 ? single.MapToIPv4() : single).Equals(ip);
    }

    public static bool IsValidWhitelistEntry(string entry)
    {
        entry = entry.Trim();
        if (entry.Contains('/'))
            return RangeSet.TryParse(entry, out _, out _);
        int dash = entry.IndexOf('-');
        if (dash > 0)
            return IPAddress.TryParse(entry[..dash].Trim(), out _) && IPAddress.TryParse(entry[(dash + 1)..].Trim(), out _);
        return IPAddress.TryParse(entry, out _);
    }

    private static List<IPAddress>? _localAddresses;
    private static DateTime _localAddressesTime;

    public static IReadOnlyList<IPAddress> LocalAddresses
    {
        get
        {
            if (_localAddresses == null || DateTime.Now - _localAddressesTime > TimeSpan.FromMinutes(5))
            {
                var list = new List<IPAddress> { IPAddress.Loopback, IPAddress.IPv6Loopback };
                try { list.AddRange(Dns.GetHostAddresses(Dns.GetHostName())); } catch { }
                _localAddresses = list;
                _localAddressesTime = DateTime.Now;
            }
            return _localAddresses;
        }
    }
}

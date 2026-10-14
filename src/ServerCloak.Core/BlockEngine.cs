namespace ServerCloak.Core;

/// <summary>Pushes the database state to Windows Firewall. Used by both the service and the app.</summary>
public static class BlockEngine
{
    private static readonly object Sync = new();

    public static bool DryRun => CloakStore.GetBool(CloakStore.KeyDryRun, false);

    /// <summary>Blocked IP addresses. In test mode nothing is blocked.</summary>
    public static void SyncIps()
    {
        lock (Sync)
            FirewallPolicyManager.Instance.SyncBlockList(DryRun ? [] : CloakStore.GetBlockedIps());
    }

    public record RangeSummary(int CountryRanges, int FeedRanges, int Entries);

    /// <summary>Builds the country and block list ranges, removes whitelisted and private addresses and updates the rules.</summary>
    public static RangeSummary SyncRanges()
    {
        lock (Sync)
        {
            var mode = CloakStore.GetCountryMode();
            var countries = new RangeSet();
            if (mode != CountryMode.Off)
            {
                var codes = CloakStore.GetCountryRules();
                // Allowing nothing would block the whole internet; ignore until countries are picked.
                if (codes.Count > 0)
                    countries = GeoIp.RangesFor(codes, invert: mode == CountryMode.AllowListed);
            }

            var feeds = new RangeSet();
            feeds.AddRange(BlockFeeds.EnabledEntries());

            var all = new RangeSet();
            foreach (var (s, e) in countries.Ranges.Concat(feeds.Ranges))
                all.Add(s, e);
            all.Subtract(CloakStore.GetNeverBlock());

            var entries = all.ToFirewallEntries();
            FirewallPolicyManager.Instance.SyncRanges(DryRun ? [] : entries);
            return new RangeSummary(countries.Count, feeds.Count, entries.Count);
        }
    }

    public static void SyncAll()
    {
        SyncIps();
        SyncRanges();
    }
}

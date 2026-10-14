using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using NetFwTypeLib;

namespace ServerCloak.Core;

/// <summary>Windows Defender Firewall access through INetFwPolicy2 (Windows Server 2016 and later).</summary>
public class FirewallPolicyManager
{
    public const string Group = "ServerCloak";
    public const string RulePrefix = "ServerCloak Block ";
    public const string RangePrefix = "ServerCloak Range ";
    public const string DynamicRuleName = "ServerCloak Block (dynamic keyword)";
    public const string DynamicKeyword = "ServerCloakBlocked";
    private const int AddressesPerRule = 1000;
    // Dynamic keyword lists cannot be empty; this address is never routable.
    private const string EmptyPlaceholder = "255.255.255.255";

    private static readonly Lazy<FirewallPolicyManager> _instance = new(() => new FirewallPolicyManager());
    public static FirewallPolicyManager Instance => _instance.Value;

    private readonly object _sync = new();
    private static INetFwPolicy2 Policy => (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!)!;

    private static readonly NET_FW_PROFILE_TYPE2_[] Profiles =
    [
        NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN,
        NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE,
        NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC
    ];

    /// <summary>True when the firewall is on for every profile.</summary>
    public bool FirewallEnabled
    {
        get
        {
            var policy = Policy;
            return Profiles.All(p => policy.get_FirewallEnabled(p));
        }
    }

    /// <summary>Turns the firewall back on for any profile where it was switched off. Returns true if something changed.</summary>
    public bool EnsureFirewallEnabled()
    {
        var policy = Policy;
        bool changed = false;
        foreach (var p in Profiles)
            if (!policy.get_FirewallEnabled(p))
            {
                policy.set_FirewallEnabled(p, true);
                changed = true;
            }
        return changed;
    }

    public string Mode { get; private set; } = "Firewall rules";

    /// <summary>Makes the firewall block exactly the given IP addresses.</summary>
    public void SyncBlockList(IReadOnlyCollection<string> ips)
    {
        lock (_sync)
        {
            bool useDynamic = OsInfo.SupportsDynamicKeywords && CloakStore.GetSetting(CloakStore.KeyUseDynamicKeywords) != "false";
            if (useDynamic && TrySyncDynamicKeyword(ips))
            {
                SyncShardRules(RulePrefix, []);
                Mode = "Dynamic keyword (Server 2022+)";
                return;
            }
            RemoveDynamicKeyword();
            SyncShardRules(RulePrefix, ips);
            Mode = "Firewall rules";
        }
    }

    /// <summary>Country and block list ranges, kept in their own "ServerCloak Range" rules.</summary>
    public void SyncRanges(IReadOnlyCollection<string> entries)
    {
        lock (_sync)
            SyncShardRules(RangePrefix, entries);
    }

    /// <summary>Removes every ServerCloak rule and the dynamic keyword (used when uninstalling).</summary>
    public void RemoveAll()
    {
        lock (_sync)
        {
            RemoveDynamicKeyword();
            SyncShardRules(RulePrefix, []);
            SyncShardRules(RangePrefix, []);
        }
    }

    public int CountRules(string prefix)
    {
        int n = 0;
        foreach (INetFwRule rule in Policy.Rules)
            if (rule.Name != null && rule.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                n++;
        return n;
    }

    private static void SyncShardRules(string prefix, IReadOnlyCollection<string> ips)
    {
        var policy = Policy;
        var existing = new Dictionary<string, INetFwRule>(StringComparer.OrdinalIgnoreCase);
        foreach (INetFwRule rule in policy.Rules)
            if (rule.Name != null && rule.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && rule.Name != DynamicRuleName)
                existing[rule.Name] = rule;

        var chunks = (prefix == RangePrefix ? ips.AsEnumerable() : ips.Order()).Chunk(AddressesPerRule).ToList();
        var wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < chunks.Count; i++)
        {
            var name = $"{prefix}{i + 1:000}";
            wanted.Add(name);
            var addresses = string.Join(",", chunks[i]);
            var description = $"Blocked by ServerCloak{(prefix == RangePrefix ? " country and block list" : "")} ({chunks[i].Length} addresses, {Hash(addresses)})";

            if (existing.TryGetValue(name, out var rule))
            {
                if (rule.Description != description)
                {
                    rule.RemoteAddresses = addresses;
                    rule.Description = description;
                }
                rule.Enabled = true;
            }
            else
            {
                rule = (INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true)!)!;
                rule.Name = name;
                rule.Description = description;
                rule.Grouping = Group;
                rule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
                rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                rule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                rule.Profiles = (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL;
                rule.RemoteAddresses = addresses;
                rule.Enabled = true;
                policy.Rules.Add(rule);
            }
        }

        foreach (var name in existing.Keys.Where(x => !wanted.Contains(x)))
            policy.Rules.Remove(name);
    }

    private static string Hash(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s)))[..12];

    public bool IsBlockRulePresent()
    {
        foreach (INetFwRule rule in Policy.Rules)
            if (rule.Name != null && rule.Name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase) && rule.Enabled)
                return true;
        return false;
    }

    // Dynamic keywords (Windows Server 2022+): the block list lives in one keyword object that a single rule references,
    // so updates do not rewrite firewall rules.

    private bool TrySyncDynamicKeyword(IReadOnlyCollection<string> ips)
    {
        try
        {
            var addresses = ips.Count == 0 ? EmptyPlaceholder : string.Join(",", ips.Order());
            var id = GetKeywordId();

            uint rc = NativeMethods.FWUpdateDynamicKeywordAddress0(id, addresses, false);
            if (rc != 0)
            {
                var entry = new NativeMethods.FW_DYNAMIC_KEYWORD_ADDRESS0 { id = id, keyword = DynamicKeyword, flags = 0, addresses = addresses };
                rc = NativeMethods.FWAddDynamicKeywordAddress0(ref entry);
                if (rc != 0)
                    throw new InvalidOperationException($"FWAddDynamicKeywordAddress0 failed with {rc}.");
            }

            if (!RuleExists(DynamicRuleName))
                CreateDynamicRule(id);
            return RuleExists(DynamicRuleName);
        }
        catch (Exception ex)
        {
            AppPaths.LogError("Dynamic keyword sync failed, falling back to firewall rules", ex);
            return false;
        }
    }

    private static Guid GetKeywordId()
    {
        if (Guid.TryParse(CloakStore.GetSetting(CloakStore.KeyDynamicKeywordId), out var id))
            return id;
        id = Guid.NewGuid();
        CloakStore.SetSetting(CloakStore.KeyDynamicKeywordId, id.ToString());
        return id;
    }

    private static bool RuleExists(string name)
    {
        foreach (INetFwRule rule in Policy.Rules)
            if (string.Equals(rule.Name, name, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    // INetFwPolicy2 cannot reference dynamic keywords, so the rule is created once through the NetSecurity module.
    private static void CreateDynamicRule(Guid id)
    {
        var command = $"New-NetFirewallRule -DisplayName '{DynamicRuleName}' -Group '{Group}' -Description 'Blocked by ServerCloak' " +
                      $"-Direction Inbound -Action Block -Profile Any -RemoteDynamicKeywordAddresses '{{{id}}}' | Out-Null";
        var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command}\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardError = true
        };
        using var p = Process.Start(psi)!;
        var error = p.StandardError.ReadToEnd();
        p.WaitForExit(60000);
        if (p.ExitCode != 0)
            throw new InvalidOperationException($"New-NetFirewallRule failed: {error}");
    }

    private void RemoveDynamicKeyword()
    {
        try
        {
            if (RuleExists(DynamicRuleName))
                Policy.Rules.Remove(DynamicRuleName);
            if (OsInfo.SupportsDynamicKeywords && Guid.TryParse(CloakStore.GetSetting(CloakStore.KeyDynamicKeywordId), out var id))
                NativeMethods.FWDeleteDynamicKeywordAddress0(id);
        }
        catch (Exception ex)
        {
            AppPaths.LogError("Remove dynamic keyword", ex);
        }
    }

    private static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct FW_DYNAMIC_KEYWORD_ADDRESS0
        {
            public Guid id;
            public string keyword;
            public uint flags;
            public string addresses;
        }

        [DllImport("firewallapi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint FWAddDynamicKeywordAddress0(ref FW_DYNAMIC_KEYWORD_ADDRESS0 dynamicKeywordAddress);

        [DllImport("firewallapi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint FWUpdateDynamicKeywordAddress0(Guid dynamicKeywordAddressId, string updatedAddresses, [MarshalAs(UnmanagedType.Bool)] bool append);

        [DllImport("firewallapi.dll")]
        internal static extern uint FWDeleteDynamicKeywordAddress0(Guid dynamicKeywordAddressId);
    }
}

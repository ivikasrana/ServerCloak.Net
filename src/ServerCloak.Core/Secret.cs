using System.Security.Cryptography;
using System.Text;

namespace ServerCloak.Core;

/// <summary>Encrypts stored secrets (SMTP password, webhook URL, API keys) with DPAPI for this machine, so both the service and the app can read them.</summary>
public static class Secret
{
    private const string Prefix = "dpapi:";
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("ServerCloak");

    public static string Protect(string value)
    {
        if (string.IsNullOrEmpty(value))
            return "";
        var data = ProtectedData.Protect(Encoding.UTF8.GetBytes(value), Entropy, DataProtectionScope.LocalMachine);
        return Prefix + Convert.ToBase64String(data);
    }

    public static string Unprotect(string? stored)
    {
        if (string.IsNullOrEmpty(stored))
            return "";
        if (!stored.StartsWith(Prefix, StringComparison.Ordinal))
            return stored;
        try
        {
            var data = ProtectedData.Unprotect(Convert.FromBase64String(stored[Prefix.Length..]), Entropy, DataProtectionScope.LocalMachine);
            return Encoding.UTF8.GetString(data);
        }
        catch (CryptographicException)
        {
            return "";
        }
    }
}

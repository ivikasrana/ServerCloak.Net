using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ServerCloak.Core;

namespace ServerCloak.App;

/// <summary>Checks GitHub releases for a newer version and runs its installer.</summary>
public static class Updater
{
    public const string DefaultRepo = "vikasrulez/ServerCloak";

    public record Release(Version Version, string Tag, string Url, string? InstallerUrl, string? InstallerName, string Notes);

    public static string Repo => CloakStore.GetSetting(CloakStore.KeyUpdateRepo) is { Length: > 0 } r ? r : DefaultRepo;

    private static HttpClient NewClient()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"ServerCloak/{AppPaths.Version}");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return http;
    }

    /// <summary>Returns the latest release when it is newer than this version, otherwise null.</summary>
    public static async Task<Release?> CheckAsync()
    {
        using var http = NewClient();
        using var resp = await http.GetAsync($"https://api.github.com/repos/{Repo}/releases/latest");
        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            return null;
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        var tag = root.GetProperty("tag_name").GetString() ?? "";
        if (!Version.TryParse(tag.TrimStart('v', 'V'), out var version))
            return null;
        CloakStore.SetSetting(CloakStore.KeyUpdateChecked, DateTime.Now.ToString("o"));

        string? installer = null, name = null;
        if (root.TryGetProperty("assets", out var assets))
            foreach (var a in assets.EnumerateArray())
            {
                var n = a.GetProperty("name").GetString() ?? "";
                if (n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && n.Contains("Setup", StringComparison.OrdinalIgnoreCase))
                {
                    installer = a.GetProperty("browser_download_url").GetString();
                    name = n;
                }
            }

        var current = Version.Parse(AppPaths.Version);
        return version > current
            ? new Release(version, tag, root.GetProperty("html_url").GetString() ?? "", installer, name, root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "")
            : null;
    }

    public static bool ShouldAutoCheck()
        => !DateTime.TryParse(CloakStore.GetSetting(CloakStore.KeyUpdateChecked), out var last) || DateTime.Now - last > TimeSpan.FromDays(1);

    /// <summary>Downloads the installer and checks its signature. Returns the file path.</summary>
    public static async Task<string> DownloadAsync(Release release)
    {
        if (release.InstallerUrl == null)
            throw new InvalidOperationException("This release has no installer attached.");
        var dir = Path.Combine(Path.GetTempPath(), "ServerCloakUpdate");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, Path.GetFileName(release.InstallerName ?? "ServerCloak-Setup.exe"));
        using (var http = NewClient())
        await using (var src = await http.GetStreamAsync(release.InstallerUrl))
        await using (var dst = File.Create(path))
            await src.CopyToAsync(dst);

        // When this build is signed, the update must be signed by the same publisher.
        var mine = Signer(Environment.ProcessPath!);
        if (mine != null)
        {
            if (!IsTrusted(path))
                throw new InvalidOperationException("The downloaded installer does not have a valid signature.");
            if (!string.Equals(Signer(path), mine, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The downloaded installer is signed by a different publisher.");
        }
        return path;
    }

    public static bool IsSigned => Signer(Environment.ProcessPath!) != null;

    public static void RunInstaller(string path)
        => Process.Start(new ProcessStartInfo(path, "/SILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS") { UseShellExecute = true });

    private static string? Signer(string file)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(file));
#pragma warning restore SYSLIB0057
            return cert.Subject;
        }
        catch { return null; }
    }

    // WinVerifyTrust: checks the Authenticode signature and the file hash.

    private static bool IsTrusted(string file)
    {
        var fileInfo = new WINTRUST_FILE_INFO { cbStruct = Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = file };
        var pFile = Marshal.AllocHGlobal(fileInfo.cbStruct);
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = 2, // WTD_UI_NONE
                fdwRevocationChecks = 0,
                dwUnionChoice = 1, // WTD_CHOICE_FILE
                pFile = pFile,
                dwStateAction = 0,
                dwProvFlags = 0x10 // WTD_REVOCATION_CHECK_NONE
            };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
            return WinVerifyTrust(IntPtr.Zero, action, ref data) == 0;
        }
        finally
        {
            Marshal.FreeHGlobal(pFile);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public int cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public int cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public int dwUIChoice;
        public int fdwRevocationChecks;
        public int dwUnionChoice;
        public IntPtr pFile;
        public int dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public int dwProvFlags;
        public int dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref WINTRUST_DATA data);
}

using System.Text;
using System.Text.RegularExpressions;
using ServerCloak.Core;

namespace ServerCloak.Service.Cloaks;

/// <summary>
/// Tails text log files. The log path may end with a wildcard folder such as C:\inetpub\logs\LogFiles\W3SVC*.
/// Only lines written after the service starts are read.
/// </summary>
public abstract class LogTailCloak(CloakSetting setting, ILogger logger, string fileFilter) : Cloak(setting, logger)
{
    private readonly Dictionary<string, long> _positions = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _timer;
    private int _busy;

    public override void Start()
    {
        foreach (var file in LogFiles())
            _positions[file] = new FileInfo(file).Length;
        _timer = new Timer(_ => Poll(), null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
        Active = true;
        Logger.LogInformation("{Cloak} is reading {Filter} in {Path}.", Setting.Name, fileFilter, Setting.LogPath);
    }

    public override void Stop()
    {
        _timer?.Dispose();
        _timer = null;
        Active = false;
    }

    private IEnumerable<string> LogFiles()
    {
        var path = Environment.ExpandEnvironmentVariables(Setting.LogPath ?? "");
        if (path.Length == 0)
            return [];
        IEnumerable<string> folders;
        var leaf = Path.GetFileName(path);
        var parent = Path.GetDirectoryName(path);
        if (leaf.Contains('*') && parent != null)
            folders = Directory.Exists(parent) ? Directory.EnumerateDirectories(parent, leaf) : [];
        else
            folders = Directory.Exists(path) ? [path] : [];
        return folders.SelectMany(f => Directory.EnumerateFiles(f, fileFilter));
    }

    private void Poll()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1)
            return;
        try
        {
            foreach (var file in LogFiles())
                ReadNewLines(file);
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "{Cloak}: reading logs failed.", Setting.Name);
        }
        finally
        {
            Interlocked.Exchange(ref _busy, 0);
        }
    }

    private void ReadNewLines(string file)
    {
        _positions.TryGetValue(file, out var position);
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (fs.Length < position)
            position = 0;
        if (fs.Length == position)
            return;
        fs.Seek(position, SeekOrigin.Begin);

        using var reader = new StreamReader(fs, Encoding.UTF8, true, 65536, leaveOpen: true);
        var text = reader.ReadToEnd();
        // Keep a partial last line for the next poll.
        int lastNewLine = text.LastIndexOf('\n');
        if (lastNewLine < 0)
            return;
        _positions[file] = position + Encoding.UTF8.GetByteCount(text.AsSpan(0, lastNewLine + 1));

        foreach (var raw in text[..lastNewLine].Split('\n'))
            ProcessLine(file, raw.TrimEnd('\r'));
    }

    protected abstract void ProcessLine(string file, string line);
}

/// <summary>IIS W3C logs (web, FTP, SMTP), with field names taken from the #Fields header.</summary>
public class IisLogCloak(CloakSetting setting, ILogger logger, Func<IReadOnlyDictionary<string, string>, bool> isFailure, string message)
    : LogTailCloak(setting, logger, "*.log")
{
    private readonly Dictionary<string, string[]> _fields = new(StringComparer.OrdinalIgnoreCase);

    protected override void ProcessLine(string file, string line)
    {
        if (line.StartsWith("#Fields:", StringComparison.Ordinal))
        {
            _fields[file] = line[8..].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return;
        }
        if (line.Length == 0 || line[0] == '#')
            return;
        if (!_fields.TryGetValue(file, out var names))
            names = ReadFieldsHeader(file);
        if (names.Length == 0)
            return;

        var row = ParseRow(names, line);
        if (isFailure(row) && row.TryGetValue("c-ip", out var ip))
        {
            var user = LogParsers.Clean(Uri.UnescapeDataString(Get(row, "cs-username").Replace('+', ' ')));
            Raise(new Hit(ip, user), 0, user == null ? message : $"{message}, user {user}");
        }
    }

    public static Dictionary<string, string> ParseRow(string[] names, string line)
    {
        var values = line.Split(' ');
        var row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < names.Length && i < values.Length; i++)
            row[names[i]] = values[i];
        return row;
    }

    // A file opened mid-way still needs the #Fields header from its start.
    private string[] ReadFieldsHeader(string file)
    {
        string[] names = [];
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(fs);
        string? line;
        int count = 0;
        while ((line = reader.ReadLine()) != null && count++ < 2000)
            if (line.StartsWith("#Fields:", StringComparison.Ordinal))
                names = line[8..].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        _fields[file] = names;
        return names;
    }

    // Failure detectors

    public static string Get(IReadOnlyDictionary<string, string> row, string name) => row.TryGetValue(name, out var v) ? v : "";

    /// <summary>HTTP 401.1: logon failed because of invalid credentials.</summary>
    public static bool IsWebLogonFailure(IReadOnlyDictionary<string, string> row)
        => Get(row, "sc-status") == "401" && (Get(row, "sc-substatus") is "1" or "");

    public static bool IsFtpLogonFailure(IReadOnlyDictionary<string, string> row)
        => Get(row, "cs-method").Equals("PASS", StringComparison.OrdinalIgnoreCase) && Get(row, "sc-status") == "530";

    public static bool IsSmtpAuthFailure(IReadOnlyDictionary<string, string> row)
        => Get(row, "sc-status") == "535";

    private static readonly string[] ExchangePaths =
        ["/owa", "/ecp", "/ews", "/microsoft-server-activesync", "/mapi", "/rpc", "/autodiscover", "/oab", "/powershell"];

    /// <summary>Exchange: 401.1 on the client access paths.</summary>
    public static bool IsExchangeLogonFailure(IReadOnlyDictionary<string, string> row)
    {
        if (!IsWebLogonFailure(row))
            return false;
        var path = Get(row, "cs-uri-stem");
        return ExchangePaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>RD Web Access: a failed sign-in posts to login.aspx and gets the page back (200); success redirects (302).</summary>
    public static bool IsRdWebLogonFailure(IReadOnlyDictionary<string, string> row)
        => Get(row, "cs-method").Equals("POST", StringComparison.OrdinalIgnoreCase)
           && Get(row, "sc-status") == "200"
           && Get(row, "cs-uri-stem").StartsWith("/RDWeb/", StringComparison.OrdinalIgnoreCase)
           && Get(row, "cs-uri-stem").EndsWith("/login.aspx", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Custom rule for any text log: every line matching the pattern counts as one failed attempt.</summary>
public class RegexLogCloak(CloakSetting setting, ILogger logger, Regex pattern)
    : LogTailCloak(setting, logger, string.IsNullOrWhiteSpace(setting.FileFilter) ? "*.log" : setting.FileFilter!)
{
    protected override void ProcessLine(string file, string line)
    {
        if (line.Length == 0 || LogParsers.ParseCustom(pattern, line) is not { } hit)
            return;
        Raise(hit, 0, hit.User == null ? Setting.Name : $"{Setting.Name}, user {hit.User}");
    }
}

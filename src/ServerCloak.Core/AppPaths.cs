namespace ServerCloak.Core;

public static class AppPaths
{
    public const string ServiceName = "ServerCloakService";
    public const string ServiceExe = "ServerCloakService.exe";
    public const string EventSource = "ServerCloak";

    public static string DataDir { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ServerCloak");

    public static string DbPath => Path.Combine(DataDir, "servercloak.db");

    public static string LogDbPath => Path.Combine(DataDir, "servercloak-logs.db");

    public static string ErrorLogPath => Path.Combine(DataDir, "ErrorLog.txt");

    public static string Version => typeof(AppPaths).Assembly.GetName().Version?.ToString(3) ?? "3.0.0";

    public static void EnsureDataDir() => Directory.CreateDirectory(DataDir);

    public static void LogError(string context, Exception ex)
    {
        try
        {
            EnsureDataDir();
            File.AppendAllText(ErrorLogPath, $"{Environment.NewLine}{DateTime.Now:yyyy-MM-dd HH:mm:ss} {context}{Environment.NewLine}{ex}{Environment.NewLine}");
        }
        catch { }
    }
}

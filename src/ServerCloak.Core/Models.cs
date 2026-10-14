namespace ServerCloak.Core;

public enum BlockDurationEnum
{
    Permanent = 0,
    Day = 1,
    Week = 7,
    Month = 30,
    Month3 = 90,
    Year = 365
}

public enum CloakEnum
{
    Manual = 1,
    ActiveDirectory = 100,
    FileMaker = 200,
    Ftp = 300,
    Kerberos = 400,
    Rdp = 500,
    RoutingAndRemoteAccess = 600,
    Smtp = 700,
    Sql = 800,
    WindowsSecurity = 900,
    WindowsLogon = 1000,
    OpenSsh = 1100,
    IisWeb = 1200,
    IisFtp = 1300,
    IisSmtp = 1400,
    Exchange = 1500,
    RdWeb = 1600,
    RdGateway = 1700,
    // Custom rules use ids from 10000 up.
    CustomBase = 10000
}

public enum CloakKind
{
    EventLog,
    PacketSniffer,
    LogFile
}

public enum CountryMode
{
    Off,
    BlockListed,
    AllowListed
}

public enum FeedFormat
{
    /// <summary>One IP, range or CIDR per line; # and ; start comments. Spamhaus JSON lines are also understood.</summary>
    Text,
    /// <summary>AbuseIPDB blacklist API, needs an API key.</summary>
    AbuseIpDb
}

public enum NotificationLevel
{
    Info,
    Block,
    Warning,
    Summary
}

/// <summary>One failed attempt found by a cloak.</summary>
public record Hit(string? Ip, string? User = null, bool RealAccount = false);

public class AttackDetectedEventArgs
{
    public CloakEnum CloakName { get; set; }
    public DateTime CreateDate { get; set; }
    public int EventId { get; set; }
    public string? EventMessage { get; set; }
    public string IpAddress { get; set; } = "";
    public string? Username { get; set; }
    public bool RealAccount { get; set; }
}

public class CloakSetting
{
    public CloakEnum Id { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public CloakKind Kind { get; set; }
    public bool Enabled { get; set; } = true;
    public int Port { get; set; }
    public int Limit { get; set; } = 5;
    public BlockDurationEnum BlockDuration { get; set; } = BlockDurationEnum.Month3;
    public string? LogPath { get; set; }

    // Custom rules
    public bool IsCustom { get; set; }
    /// <summary>Event log name for custom event log rules.</summary>
    public string? EventLogName { get; set; }
    /// <summary>Comma separated event ids for custom event log rules.</summary>
    public string? EventIds { get; set; }
    /// <summary>Regex with a named group "ip" (and optionally "user"). Required for log files, optional for event logs.</summary>
    public string? Pattern { get; set; }
    /// <summary>File name filter for custom log file rules, for example *.log.</summary>
    public string? FileFilter { get; set; }
}

public class IpLog
{
    public int Id { get; set; }
    public string Ip { get; set; } = "";
    public CloakEnum Cloak { get; set; }
    public int Attacks { get; set; }
    public DateTime Created { get; set; }
    public DateTime LastSeen { get; set; }
    public DateTime? Locked { get; set; }
    /// <summary>When the block ends; null while blocked means permanent.</summary>
    public DateTime? Expires { get; set; }
    public string? Country { get; set; }
}

/// <summary>Block history per address, used for repeat offender escalation.</summary>
public class Offender
{
    public string Ip { get; set; } = "";
    public int Strikes { get; set; }
    public DateTime LastBlocked { get; set; }
}

public class CountryRule
{
    public string Code { get; set; } = "";
}

public class FeedSource
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Url { get; set; } = "";
    public FeedFormat Format { get; set; }
    public bool Enabled { get; set; }
    public DateTime? Updated { get; set; }
    public int Count { get; set; }
    public string? LastError { get; set; }
}

public class FeedEntry
{
    public long Id { get; set; }
    public int SourceId { get; set; }
    public string Value { get; set; } = "";
}

public class WhitelistEntry
{
    public int Id { get; set; }
    public string Value { get; set; } = "";
}

public class Setting
{
    public string Key { get; set; } = "";
    public string Value { get; set; } = "";
}

public class GeoRange
{
    public long Id { get; set; }
    public byte[] StartIp { get; set; } = [];
    public byte[] EndIp { get; set; } = [];
    public string Country { get; set; } = "";
}

// Logs database

public class AttackEvent
{
    public long Id { get; set; }
    public string Ip { get; set; } = "";
    public CloakEnum Cloak { get; set; }
    public int EventId { get; set; }
    public string? Message { get; set; }
    public string? Username { get; set; }
    public bool RealAccount { get; set; }
    public bool Blocked { get; set; }
    public DateTime Time { get; set; }
}

/// <summary>Messages from the service for the tray icon.</summary>
public class Notification
{
    public long Id { get; set; }
    public DateTime Time { get; set; }
    public NotificationLevel Level { get; set; }
    public string Title { get; set; } = "";
    public string Text { get; set; } = "";
}

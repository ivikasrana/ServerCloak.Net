using System.ComponentModel;
using System.Runtime.CompilerServices;
using ServerCloak.Core;

namespace ServerCloak.App;

public abstract class Observable : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
            return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}

public record DurationOption(BlockDurationEnum Value, string Label)
{
    public static IReadOnlyList<DurationOption> All { get; } =
    [
        new(BlockDurationEnum.Day, "1 day"),
        new(BlockDurationEnum.Week, "1 week"),
        new(BlockDurationEnum.Month, "1 month"),
        new(BlockDurationEnum.Month3, "3 months"),
        new(BlockDurationEnum.Year, "1 year"),
        new(BlockDurationEnum.Permanent, "Permanent")
    ];
}

public class CloakRow : Observable
{
    private int _attacks;
    private int _blocked;

    public CloakRow(CloakSetting s)
    {
        Id = s.Id;
        Name = s.Name;
        Description = s.Description;
        Kind = s.Kind;
        Enabled = s.Enabled;
        Port = s.Port;
        Limit = s.Limit;
        BlockDuration = s.BlockDuration;
        LogPath = s.LogPath;
        IsCustom = s.IsCustom;
        Source = s;
    }

    public CloakSetting Source { get; }
    public bool IsCustom { get; }

    public CloakEnum Id { get; }
    public string Name { get; }
    public string Description { get; }
    public CloakKind Kind { get; }
    public bool Enabled { get; set; }
    public int Port { get; set; }
    public int Limit { get; set; }
    public BlockDurationEnum BlockDuration { get; set; }
    public string? LogPath { get; set; }

    public bool IsSniffer => Kind == CloakKind.PacketSniffer;
    public bool IsLogFile => Kind == CloakKind.LogFile && !IsCustom;
    public string KindLabel => Kind switch
    {
        CloakKind.EventLog => "Event log",
        CloakKind.PacketSniffer => "Packet sniffer",
        _ => "Log file"
    } + (IsCustom ? " (custom)" : "");

    public int Attacks { get => _attacks; set => Set(ref _attacks, value); }
    public int Blocked { get => _blocked; set => Set(ref _blocked, value); }

    public CloakSetting ToSetting() => new()
    {
        Id = Id, Enabled = Enabled, Port = Port, Limit = Limit, BlockDuration = BlockDuration, LogPath = LogPath
    };
}

public class IpRow
{
    public IpRow(IpLog x, IReadOnlyDictionary<CloakEnum, string> names)
    {
        Ip = x.Ip;
        CountryCode = string.IsNullOrEmpty(x.Country) ? "--" : x.Country;
        Country = GeoIp.CountryName(x.Country);
        Cloak = names.TryGetValue(x.Cloak, out var n) ? n : x.Cloak == CloakEnum.Manual ? "Manual" : x.Cloak.ToString();
        Attacks = x.Attacks;
        Created = x.Created;
        LastSeen = x.LastSeen;
        Locked = x.Locked;
        Expires = x.Expires;
    }

    public DateTime? Expires { get; }
    public string UntilText => Locked == null ? "" : Expires == null ? "Permanent" : Expires.Value.ToString("dd MMM yyyy HH:mm");

    public string Ip { get; }
    public string CountryCode { get; }
    public string Country { get; }
    public string Cloak { get; }
    public int Attacks { get; }
    public DateTime Created { get; }
    public DateTime LastSeen { get; }
    public DateTime? Locked { get; }
    public bool IsBlocked => Locked != null;
    public string LockedText => Locked?.ToString("dd MMM yyyy HH:mm") ?? "";
}

public class CountryRow
{
    public string Code { get; init; } = "";
    public string Name { get; init; } = "";
    public int Ips { get; init; }
    public int Attacks { get; init; }
    public int Blocked { get; init; }
    public double Bar { get; init; }
}

public class EventRow
{
    public string Time { get; init; } = "";
    public string Ip { get; init; } = "";
    public string Cloak { get; init; } = "";
    public string Message { get; init; } = "";
}

public class FeatureRow
{
    public string Name { get; init; } = "";
    public bool Available { get; init; }
    public string Note { get; init; } = "";
    public string Glyph => Available ? "\uE73E" : "\uE711";
}

public class CloakFilter
{
    public CloakEnum? Id { get; init; }
    public string Name { get; init; } = "";
}

public class UserRow
{
    public string User { get; init; } = "";
    public int Attempts { get; init; }
    public int Ips { get; init; }
    public bool RealAccount { get; init; }
}

public class FeedRow : Observable
{
    private bool _enabled;

    public FeedRow(FeedSource f)
    {
        Id = f.Id;
        Name = f.Name;
        Url = f.Url;
        Format = f.Format;
        _enabled = f.Enabled;
        Status = f.LastError != null ? $"Error: {f.LastError}"
            : f.Updated == null ? "Not downloaded yet"
            : $"{f.Count:N0} entries, updated {f.Updated:dd MMM HH:mm}";
        HasError = f.LastError != null;
    }

    public int Id { get; }
    public string Name { get; }
    public string Url { get; }
    public FeedFormat Format { get; }
    public string Status { get; }
    public bool HasError { get; }
    public bool Enabled { get => _enabled; set => Set(ref _enabled, value); }

    public FeedSource ToSource() => new() { Id = Id, Name = Name, Url = Url, Format = Format, Enabled = Enabled };
}

public class CountryPick : Observable
{
    private bool _selected;
    public string Code { get; init; } = "";
    public string Name { get; init; } = "";
    public string Label => $"{Name} ({Code})";
    public bool Selected { get => _selected; set => Set(ref _selected, value); }
}

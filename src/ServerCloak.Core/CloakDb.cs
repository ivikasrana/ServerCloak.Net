using Microsoft.EntityFrameworkCore;

namespace ServerCloak.Core;

/// <summary>Settings, cloaks, blocks, whitelist, country and block list data (servercloak.db).</summary>
public class CloakDb : DbContext
{
    public DbSet<CloakSetting> Cloaks => Set<CloakSetting>();
    public DbSet<IpLog> IpLogs => Set<IpLog>();
    public DbSet<Offender> Offenders => Set<Offender>();
    public DbSet<WhitelistEntry> Whitelist => Set<WhitelistEntry>();
    public DbSet<Setting> Settings => Set<Setting>();
    public DbSet<GeoRange> GeoRanges => Set<GeoRange>();
    public DbSet<CountryRule> CountryRules => Set<CountryRule>();
    public DbSet<FeedSource> Feeds => Set<FeedSource>();
    public DbSet<FeedEntry> FeedEntries => Set<FeedEntry>();

    protected override void OnConfiguring(DbContextOptionsBuilder options)
        => options.UseSqlite($"Data Source={AppPaths.DbPath};Default Timeout=30");

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<CloakSetting>().HasKey(x => x.Id);
        b.Entity<CloakSetting>().Property(x => x.Id).ValueGeneratedNever();
        b.Entity<IpLog>().HasIndex(x => new { x.Ip, x.Cloak }).IsUnique();
        b.Entity<IpLog>().HasIndex(x => x.Locked);
        b.Entity<IpLog>().HasIndex(x => x.LastSeen);
        b.Entity<Offender>().HasKey(x => x.Ip);
        b.Entity<Setting>().HasKey(x => x.Key);
        b.Entity<GeoRange>().HasIndex(x => x.StartIp);
        b.Entity<CountryRule>().HasKey(x => x.Code);
        b.Entity<FeedEntry>().HasIndex(x => x.SourceId);
    }
}

/// <summary>Attack history and notifications (servercloak-logs.db), kept apart so it can grow or be cleared on its own.</summary>
public class LogDb : DbContext
{
    public DbSet<AttackEvent> AttackEvents => Set<AttackEvent>();
    public DbSet<Notification> Notifications => Set<Notification>();

    protected override void OnConfiguring(DbContextOptionsBuilder options)
        => options.UseSqlite($"Data Source={AppPaths.LogDbPath};Default Timeout=30");

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<AttackEvent>().HasIndex(x => x.Time);
        b.Entity<AttackEvent>().HasIndex(x => x.Ip);
        b.Entity<AttackEvent>().HasIndex(x => x.Username);
        b.Entity<Notification>().HasIndex(x => x.Time);
    }
}

using ServerCloak.Core;

namespace ServerCloak.Service.Cloaks;

public abstract class Cloak(CloakSetting setting, ILogger logger)
{
    public event Action<AttackDetectedEventArgs>? AttackDetected;

    public CloakSetting Setting { get; } = setting;
    protected ILogger Logger { get; } = logger;

    /// <summary>False when the source (log, folder, socket) was not available and the cloak is idle.</summary>
    public bool Active { get; protected set; }

    public abstract void Start();
    public abstract void Stop();

    protected void Raise(Hit hit, int eventId, string message, DateTime? time = null)
    {
        var normalized = IpUtil.Normalize(hit.Ip);
        if (normalized == null)
            return;
        AttackDetected?.Invoke(new AttackDetectedEventArgs
        {
            CloakName = Setting.Id,
            CreateDate = time ?? DateTime.Now,
            EventId = eventId,
            EventMessage = message,
            IpAddress = normalized,
            Username = hit.User,
            RealAccount = hit.RealAccount
        });
    }

    protected void Raise(string? ip, int eventId, string message, DateTime? time = null) => Raise(new Hit(ip), eventId, message, time);
}

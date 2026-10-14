using System.Text.RegularExpressions;
using ServerCloak.Core;
using E = ServerCloak.Service.Cloaks.EventLogCloak;
using S = ServerCloak.Service.Cloaks.PacketSnifferCloak;
using I = ServerCloak.Service.Cloaks.IisLogCloak;

namespace ServerCloak.Service.Cloaks;

public static class CloakFactory
{
    public static Cloak? Create(CloakSetting s, ILogger log)
    {
        if (s.IsCustom)
            return CreateCustom(s, log);

        return s.Id switch
        {
            CloakEnum.WindowsLogon => new E(s, log, "Security", "*[System[EventID=4625]]", E.Logon4625),
            CloakEnum.WindowsSecurity => new E(s, log, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "*[System[EventID=140]]", r => E.NamedData(r, "IPString")),
            CloakEnum.RdGateway => new E(s, log, "Microsoft-Windows-TerminalServices-Gateway/Operational", "*[System[(EventID=201 or EventID=301)]]", E.Gateway),
            CloakEnum.ActiveDirectory => new E(s, log, "Security", "*[System[EventID=4776] and EventData[Data[@Name='Status']!='0x0']]", E.ResolveWorkstation),
            CloakEnum.Kerberos => new E(s, log, "Security", "*[System[EventID=4771]]", E.Kerberos),
            CloakEnum.Sql => new E(s, log, "Application", "*[System[EventID=18456]]", E.Sql),
            CloakEnum.OpenSsh => new E(s, log, "OpenSSH/Operational", "*", E.OpenSshFailure),
            CloakEnum.RoutingAndRemoteAccess => new E(s, log, "System", "*[System[EventID=20271]]", E.AnyIp),
            CloakEnum.FileMaker => new E(s, log, "Application", "*[System[EventID=661]]", E.AnyIp),

            CloakEnum.IisWeb => new I(s, log, I.IsWebLogonFailure, "IIS 401.1 logon failure"),
            CloakEnum.Exchange => new I(s, log, I.IsExchangeLogonFailure, "Exchange logon failure"),
            CloakEnum.RdWeb => new I(s, log, I.IsRdWebLogonFailure, "RD Web Access sign-in failure"),
            CloakEnum.IisFtp => new I(s, log, I.IsFtpLogonFailure, "IIS FTP logon failure"),
            CloakEnum.IisSmtp => new I(s, log, I.IsSmtpAuthFailure, "IIS SMTP authentication failure"),

            CloakEnum.Smtp => new S(s, log, p => S.StartsWithCode(p, "535", "504"), "SMTP authentication failure"),
            CloakEnum.Ftp => new S(s, log, p => S.StartsWithCode(p, "530"), "FTP authentication failure"),
            CloakEnum.Rdp => new S(s, log, S.IsTlsAlert, "Remote desktop TLS/SSL authentication failure"),
            _ => null
        };
    }

    private static Cloak? CreateCustom(CloakSetting s, ILogger log)
    {
        var pattern = string.IsNullOrWhiteSpace(s.Pattern) ? null : new Regex(s.Pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        return s.Kind switch
        {
            CloakKind.EventLog when !string.IsNullOrWhiteSpace(s.EventLogName) => new E(s, log, s.EventLogName!, E.XPathForIds(s.EventIds), E.Custom(pattern)),
            CloakKind.LogFile when pattern != null => new RegexLogCloak(s, log, pattern),
            _ => null
        };
    }
}

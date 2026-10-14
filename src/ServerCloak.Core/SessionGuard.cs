using System.Net;
using System.Runtime.InteropServices;

namespace ServerCloak.Core;

/// <summary>
/// Self-lockout guard: the client addresses of signed-in Remote Desktop sessions are never blocked.
/// </summary>
public static class SessionGuard
{
    private static List<IPAddress> _cache = [];
    private static DateTime _cacheTime;
    private static readonly object Sync = new();

    public static IReadOnlyList<IPAddress> SessionAddresses
    {
        get
        {
            lock (Sync)
            {
                if (DateTime.Now - _cacheTime > TimeSpan.FromSeconds(30))
                {
                    try { _cache = Query(); }
                    catch (Exception ex) { AppPaths.LogError("Session guard", ex); }
                    _cacheTime = DateTime.Now;
                }
                return _cache;
            }
        }
    }

    public static bool IsProtected(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        return SessionAddresses.Any(x => x.Equals(ip));
    }

    private static List<IPAddress> Query()
    {
        var list = new List<IPAddress>();
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var sessions, out var count))
            return list;
        try
        {
            int size = Marshal.SizeOf<WTS_SESSION_INFO>();
            for (int i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WTS_SESSION_INFO>(sessions + i * size);
                if (info.State is not (WTS_CONNECTSTATE_CLASS.WTSActive or WTS_CONNECTSTATE_CLASS.WTSDisconnected))
                    continue;
                if (string.IsNullOrEmpty(QueryString(info.SessionId, WTS_INFO_CLASS.WTSUserName)))
                    continue;
                if (!WTSQuerySessionInformation(IntPtr.Zero, info.SessionId, WTS_INFO_CLASS.WTSClientAddress, out var buffer, out _))
                    continue;
                try
                {
                    var addr = Marshal.PtrToStructure<WTS_CLIENT_ADDRESS>(buffer);
                    if (addr.AddressFamily == 2)
                        list.Add(new IPAddress(addr.Address.AsSpan(2, 4)));
                    else if (addr.AddressFamily == 23)
                    {
                        // The IPv6 layout is not documented; accept both known offsets.
                        list.Add(new IPAddress(addr.Address.AsSpan(0, 16)));
                        list.Add(new IPAddress(addr.Address.AsSpan(2, 16)));
                    }
                }
                finally { WTSFreeMemory(buffer); }
            }
        }
        finally { WTSFreeMemory(sessions); }
        return list.Select(x => x.IsIPv4MappedToIPv6 ? x.MapToIPv4() : x).Where(x => !IPAddress.Any.Equals(x) && !IPAddress.IPv6Any.Equals(x)).Distinct().ToList();
    }

    private static string? QueryString(int sessionId, WTS_INFO_CLASS cls)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, cls, out var buffer, out _))
            return null;
        try { return Marshal.PtrToStringUni(buffer); }
        finally { WTSFreeMemory(buffer); }
    }

    private enum WTS_CONNECTSTATE_CLASS { WTSActive, WTSConnected, WTSConnectQuery, WTSShadow, WTSDisconnected, WTSIdle, WTSListen, WTSReset, WTSDown, WTSInit }

    private enum WTS_INFO_CLASS { WTSUserName = 5, WTSClientAddress = 14 }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WTS_SESSION_INFO
    {
        public int SessionId;
        public string pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_CLIENT_ADDRESS
    {
        public int AddressFamily;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] Address;
    }

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSEnumerateSessions(IntPtr hServer, int reserved, int version, out IntPtr sessionInfo, out int count);

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, WTS_INFO_CLASS infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
}

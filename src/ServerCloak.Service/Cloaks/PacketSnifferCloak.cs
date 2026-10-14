using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using ServerCloak.Core;

namespace ServerCloak.Service.Cloaks;

/// <summary>
/// Raw-socket sniffer (SIO_RCVALL) on every local IPv4 and IPv6 address. Looks at TCP packets the server sends from
/// the watched port and reports the destination as the attacker when the payload is a failure reply.
/// Only sees plain-text protocols; encrypted sessions need the log based cloaks.
/// </summary>
public class PacketSnifferCloak(CloakSetting setting, ILogger logger, Func<ReadOnlyMemory<byte>, bool> isFailure, string message)
    : Cloak(setting, logger)
{
    private readonly List<Socket> _sockets = [];
    private CancellationTokenSource? _cts;

    public override void Start()
    {
        _cts = new CancellationTokenSource();
        var addresses = Dns.GetHostAddresses(Dns.GetHostName())
            .Where(a => a.AddressFamily == AddressFamily.InterNetwork ||
                        a.AddressFamily == AddressFamily.InterNetworkV6 && !a.IsIPv6LinkLocal && !IPAddress.IsLoopback(a));
        foreach (var address in addresses)
        {
            try
            {
                var socket = new Socket(address.AddressFamily, SocketType.Raw, ProtocolType.IP);
                socket.Bind(new IPEndPoint(address, 0));
                if (address.AddressFamily == AddressFamily.InterNetwork)
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), new byte[4]);
                _sockets.Add(socket);
                _ = Task.Run(() => ReceiveLoop(socket, address, _cts.Token));
                Active = true;
                Logger.LogInformation("{Cloak} is listening on {Address}:{Port}.", Setting.Name, address, Setting.Port);
            }
            catch (Exception ex)
            {
                Logger.LogWarning(ex, "{Cloak} could not open a raw socket on {Address}.", Setting.Name, address);
            }
        }
    }

    public override void Stop()
    {
        _cts?.Cancel();
        foreach (var s in _sockets)
            s.Dispose();
        _sockets.Clear();
        Active = false;
    }

    private async Task ReceiveLoop(Socket socket, IPAddress local, CancellationToken ct)
    {
        var buffer = new byte[65535];
        var localBytes = local.GetAddressBytes();
        while (!ct.IsCancellationRequested)
        {
            int n;
            try { n = await socket.ReceiveAsync(buffer, SocketFlags.None, ct); }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { continue; }

            try
            {
                if (FindReply(buffer.AsMemory(0, n), localBytes, Setting.Port) is { } reply && isFailure(reply.Payload))
                    Raise(reply.Remote.ToString(), 9112, message);
            }
            catch (Exception ex)
            {
                Logger.LogDebug(ex, "{Cloak}: packet parse failed.", Setting.Name);
            }
        }
    }

    public record Reply(IPAddress Remote, ReadOnlyMemory<byte> Payload);

    /// <summary>
    /// Returns the TCP payload and destination when the packet is sent by <paramref name="localBytes"/> from <paramref name="port"/>.
    /// Handles IPv4 and IPv6 (with hop-by-hop, routing and destination option headers).
    /// </summary>
    public static Reply? FindReply(ReadOnlyMemory<byte> packet, byte[] localBytes, int port)
    {
        var p = packet.Span;
        if (p.Length < 20)
            return null;
        int version = p[0] >> 4;
        int tcpStart, end;
        IPAddress remote;

        if (version == 4)
        {
            if (p[9] != (byte)ProtocolType.Tcp)
                return null;
            int ipHeader = (p[0] & 0x0F) * 4;
            end = Math.Min(BinaryPrimitives.ReadUInt16BigEndian(p[2..]), p.Length);
            if (localBytes.Length != 4 || !p.Slice(12, 4).SequenceEqual(localBytes) || end < ipHeader + 20)
                return null;
            tcpStart = ipHeader;
            remote = new IPAddress(p.Slice(16, 4));
        }
        else if (version == 6)
        {
            if (p.Length < 40 || localBytes.Length != 16 || !p.Slice(8, 16).SequenceEqual(localBytes))
                return null;
            end = Math.Min(40 + BinaryPrimitives.ReadUInt16BigEndian(p[4..]), p.Length);
            int next = p[6];
            int offset = 40;
            // Skip extension headers: hop-by-hop (0), routing (43), destination options (60).
            while (next is 0 or 43 or 60)
            {
                if (offset + 8 > end)
                    return null;
                next = p[offset];
                offset += (p[offset + 1] + 1) * 8;
            }
            if (next != (int)ProtocolType.Tcp || end < offset + 20)
                return null;
            tcpStart = offset;
            remote = new IPAddress(p.Slice(24, 16));
        }
        else
            return null;

        var tcp = p[tcpStart..end];
        if (BinaryPrimitives.ReadUInt16BigEndian(tcp) != port)
            return null;
        int tcpHeader = (tcp[12] >> 4) * 4;
        if (tcp.Length <= tcpHeader)
            return null;
        return new Reply(remote, packet[(tcpStart + tcpHeader)..end]);
    }

    // Failure detectors

    public static bool StartsWithCode(ReadOnlyMemory<byte> payload, params string[] codes)
    {
        var s = payload.Span;
        if (s.Length < 4)
            return false;
        foreach (var code in codes)
            if (s[0] == code[0] && s[1] == code[1] && s[2] == code[2] && (s[3] == ' ' || s[3] == '-'))
                return true;
        return false;
    }

    /// <summary>TLS alert record (content type 21, version 3.x) sent by the server.</summary>
    public static bool IsTlsAlert(ReadOnlyMemory<byte> payload)
    {
        var s = payload.Span;
        return s.Length >= 5 && s[0] == 0x15 && s[1] == 3 && s[2] <= 4;
    }
}

using System.Globalization;
using System.IO;
using System.Text;
using PdfSharp.Drawing;
using PdfSharp.Fonts;
using PdfSharp.Pdf;
using ServerCloak.Core;

namespace ServerCloak.App;

/// <summary>CSV and PDF reports of attacks for a period.</summary>
public static class Reports
{
    private static string Csv(string? s)
    {
        s ??= "";
        return s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? $"\"{s.Replace("\"", "\"\"")}\"" : s;
    }

    public static void ExportEventsCsv(string path, DateTime since, IReadOnlyDictionary<CloakEnum, string> names)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Time,IP,Country,Cloak,User,RealAccount,Blocked,Message");
        var countries = new Dictionary<string, string?>();
        foreach (var e in CloakStore.GetEvents(since))
        {
            if (!countries.TryGetValue(e.Ip, out var c))
                countries[e.Ip] = c = GeoIp.Lookup(e.Ip);
            sb.Append(e.Time.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)).Append(',')
              .Append(Csv(e.Ip)).Append(',')
              .Append(Csv(c)).Append(',')
              .Append(Csv(names.TryGetValue(e.Cloak, out var n) ? n : e.Cloak.ToString())).Append(',')
              .Append(Csv(e.Username)).Append(',')
              .Append(e.RealAccount ? "yes" : "").Append(',')
              .Append(e.Blocked ? "yes" : "").Append(',')
              .AppendLine(Csv(e.Message));
        }
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
    }

    public static void ExportIpsCsv(string path, IEnumerable<IpRow> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine("IP,Country,Cloak,Attempts,FirstSeen,LastSeen,Blocked,BlockedUntil");
        foreach (var r in rows)
            sb.Append(Csv(r.Ip)).Append(',').Append(Csv(r.CountryCode)).Append(',').Append(Csv(r.Cloak)).Append(',')
              .Append(r.Attacks).Append(',')
              .Append(r.Created.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)).Append(',')
              .Append(r.LastSeen.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)).Append(',')
              .Append(r.Locked?.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)).Append(',')
              .AppendLine(r.IsBlocked ? r.UntilText : "");
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
    }

    private static bool _fontsReady;

    public static void ExportPdf(string path, string periodName, DateTime since, TimeSpan bucket, string labelFormat, IReadOnlyDictionary<CloakEnum, string> names)
    {
        if (!_fontsReady)
        {
            GlobalFontSettings.UseWindowsFontsUnderWindows = true;
            _fontsReady = true;
        }

        var events = CloakStore.GetEvents(since);
        var timeline = CloakStore.GetTimeline(since, bucket);
        var users = CloakStore.GetTopUsernames(since, 10);
        var countries = new Dictionary<string, string?>();
        string? Country(string ip) => countries.TryGetValue(ip, out var c) ? c : countries[ip] = GeoIp.Lookup(ip);

        using var doc = new PdfDocument();
        doc.Info.Title = $"ServerCloak report, {periodName}";
        doc.Info.Author = "ServerCloak";
        var page = doc.AddPage();
        page.Size = PdfSharp.PageSize.A4;
        var g = XGraphics.FromPdfPage(page);

        var blue = XColor.FromArgb(0, 122, 255);
        var red = XColor.FromArgb(255, 59, 48);
        var grey = XColor.FromArgb(110, 110, 115);
        var title = new XFont("Segoe UI", 20, XFontStyleEx.Bold);
        var h2 = new XFont("Segoe UI", 12, XFontStyleEx.Bold);
        var body = new XFont("Segoe UI", 9.5, XFontStyleEx.Regular);
        var small = new XFont("Segoe UI", 8, XFontStyleEx.Regular);
        double margin = 40, width = page.Width.Point - margin * 2, y = margin;

        g.DrawString("ServerCloak report", title, XBrushes.Black, margin, y + 18);
        y += 30;
        g.DrawString($"{Environment.MachineName} · {OsInfo.ProductName} · {periodName} ({since:dd MMM yyyy HH:mm} to {DateTime.Now:dd MMM yyyy HH:mm})", body, new XSolidBrush(grey), margin, y + 10);
        y += 30;

        // Summary tiles
        var tiles = new (string Label, string Value)[]
        {
            ("Failed attempts", events.Count.ToString("N0")),
            ("Attacking addresses", events.Select(x => x.Ip).Distinct().Count().ToString("N0")),
            ("New blocks", events.Count(x => x.Blocked).ToString("N0")),
            ("Blocked now", CloakStore.GetBlockedCount().ToString("N0"))
        };
        double tw = (width - 3 * 10) / 4;
        for (int i = 0; i < tiles.Length; i++)
        {
            double x = margin + i * (tw + 10);
            g.DrawRoundedRectangle(new XSolidBrush(XColor.FromArgb(242, 242, 247)), x, y, tw, 52, 10, 10);
            g.DrawString(tiles[i].Label, small, new XSolidBrush(grey), x + 10, y + 16);
            g.DrawString(tiles[i].Value, new XFont("Segoe UI", 16, XFontStyleEx.Bold), XBrushes.Black, x + 10, y + 40);
        }
        y += 70;

        // Chart
        g.DrawString("Attempts over time", h2, XBrushes.Black, margin, y + 12);
        y += 22;
        double ch = 140, cl = margin + 30;
        int max = Math.Max(1, timeline.Select(p => p.Attempts).DefaultIfEmpty(0).Max());
        var gridPen = new XPen(XColor.FromArgb(220, 220, 225), 0.5);
        for (int i = 0; i <= 4; i++)
        {
            double gy = y + ch - ch * i / 4;
            g.DrawLine(gridPen, cl, gy, margin + width, gy);
            g.DrawString((max * i / 4).ToString("N0"), small, new XSolidBrush(grey), margin, gy + 3);
        }
        if (timeline.Count > 0)
        {
            double slot = (margin + width - cl) / timeline.Count, bar = Math.Max(0.8, slot * 0.7);
            int every = Math.Max(1, (int)Math.Ceiling(timeline.Count / 8.0));
            for (int i = 0; i < timeline.Count; i++)
            {
                var p = timeline[i];
                double x = cl + i * slot + (slot - bar) / 2;
                double ha = ch * p.Attempts / max, hb = ch * p.Blocks / max;
                if (ha > 0) g.DrawRectangle(new XSolidBrush(blue), x, y + ch - ha, bar, ha);
                if (hb > 0) g.DrawRectangle(new XSolidBrush(red), x, y + ch - hb, bar, hb);
                if (i % every == 0)
                    g.DrawString(p.Start.ToString(labelFormat), small, new XSolidBrush(grey), x, y + ch + 11);
            }
        }
        y += ch + 26;
        g.DrawRectangle(new XSolidBrush(blue), margin, y - 7, 8, 8);
        g.DrawString("attempts", small, new XSolidBrush(grey), margin + 12, y);
        g.DrawRectangle(new XSolidBrush(red), margin + 70, y - 7, 8, 8);
        g.DrawString("blocks", small, new XSolidBrush(grey), margin + 82, y);
        y += 20;

        // Tables
        void Table(string heading, double x, double w, IEnumerable<string[]> rows, double[] cols)
        {
            double ty = y;
            g.DrawString(heading, h2, XBrushes.Black, x, ty + 12);
            ty += 24;
            foreach (var r in rows)
            {
                double cx = x;
                for (int c = 0; c < r.Length; c++)
                {
                    var text = r[c];
                    while (text.Length > 3 && g.MeasureString(text, body).Width > cols[c] * w - 6)
                        text = text[..^2] + "…";
                    g.DrawString(text, body, XBrushes.Black, cx, ty);
                    cx += cols[c] * w;
                }
                ty += 15;
            }
        }

        double half = (width - 20) / 2;
        var byCountry = events.GroupBy(x => Country(x.Ip) ?? "").OrderByDescending(x => x.Count()).Take(10)
            .Select(x => new[] { GeoIp.CountryName(x.Key), x.Count().ToString("N0"), x.Select(e => e.Ip).Distinct().Count().ToString("N0") + " IPs" });
        Table("Top countries", margin, half, byCountry, [0.55, 0.22, 0.23]);
        var byCloak = events.GroupBy(x => x.Cloak).OrderByDescending(x => x.Count()).Take(10)
            .Select(x => new[] { names.TryGetValue(x.Key, out var n) ? n : x.Key.ToString(), x.Count().ToString("N0"), x.Count(e => e.Blocked).ToString("N0") + " blocks" });
        Table("By cloak", margin + half + 20, half, byCloak, [0.55, 0.2, 0.25]);
        y += 24 + 15 * 10 + 16;

        var topIps = events.GroupBy(x => x.Ip).OrderByDescending(x => x.Count()).Take(12)
            .Select(x => new[] { x.Key, GeoIp.CountryName(Country(x.Key)), x.Count().ToString("N0") });
        Table("Top addresses", margin, half, topIps, [0.45, 0.35, 0.2]);
        var topUsers = users.Select(u => new[] { u.User + (u.RealAccount ? " (real)" : ""), u.Attempts.ToString("N0"), u.Ips.ToString("N0") + " IPs" });
        Table("User names tried", margin + half + 20, half, topUsers, [0.55, 0.2, 0.25]);

        g.DrawString($"Generated by ServerCloak {AppPaths.Version} on {DateTime.Now:dd MMM yyyy HH:mm}. {GeoIp.Attribution}.", small, new XSolidBrush(grey), margin, page.Height.Point - 24);
        doc.Save(path);
    }
}

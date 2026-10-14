using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace IconGen;

static class Program
{
    static readonly int[] Sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256];

    [STAThread]
    static int Main(string[] args)
    {
        var output = args.Length > 0 ? args[0] : "ServerCloak.ico";
        var images = Sizes.Select(Render).ToList();

        using var fs = File.Create(output);
        using var w = new BinaryWriter(fs);
        w.Write((short)0);
        w.Write((short)1);
        w.Write((short)images.Count);
        int offset = 6 + 16 * images.Count;
        for (int i = 0; i < images.Count; i++)
        {
            int size = Sizes[i];
            w.Write((byte)(size >= 256 ? 0 : size));
            w.Write((byte)(size >= 256 ? 0 : size));
            w.Write((byte)0);
            w.Write((byte)0);
            w.Write((short)1);
            w.Write((short)32);
            w.Write(images[i].Length);
            w.Write(offset);
            offset += images[i].Length;
        }
        foreach (var png in images)
            w.Write(png);

        Console.WriteLine($"Wrote {output}");
        return 0;
    }

    // Drawn on a 256 x 256 canvas and scaled to each size.
    static byte[] Render(int size)
    {
        var shield = Geometry.Parse("M128,14 L222,50 C222,142 190,206 128,242 C66,206 34,142 34,50 Z");
        var keyhole = Geometry.Parse("M128,82 A30,30 0 1 1 127.9,82 Z M112,128 L144,128 L154,186 L102,186 Z");
        var shine = Geometry.Parse("M128,26 L210,58 C209,92 202,120 190,144 C160,110 110,92 46,96 C45,84 46,70 46,58 Z");

        var fill = new LinearGradientBrush(Color.FromRgb(0x00, 0x7A, 0xFF), Color.FromRgb(0x89, 0x44, 0xAB), 45);
        var edge = new Pen(new SolidColorBrush(Color.FromArgb(0x55, 0xFF, 0xFF, 0xFF)), 6);
        var glass = new SolidColorBrush(Color.FromArgb(0x38, 0xFF, 0xFF, 0xFF));

        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            dc.PushTransform(new ScaleTransform(size / 256.0, size / 256.0));
            dc.DrawGeometry(fill, size >= 32 ? edge : null, shield);
            if (size >= 32)
                dc.DrawGeometry(glass, null, shine);
            dc.DrawGeometry(Brushes.White, null, keyhole);
            dc.Pop();
        }

        var bmp = new RenderTargetBitmap(size, size, 96, 96, PixelFormats.Pbgra32);
        bmp.Render(visual);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bmp));
        using var ms = new MemoryStream();
        encoder.Save(ms);
        return ms.ToArray();
    }
}

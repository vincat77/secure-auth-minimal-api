using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinFormsClient
{
  using SkiaSharp;
  using SkiaSharp.Extended.Svg;
  using System.Drawing;
  using System.Net.Http;

  public static class ImageLoader
  {
    private static readonly HttpClient http = new();

    public static async Task<Image> LoadFromUrlAsync(
      string url, int width, int height)
    {
      await using var stream = await http.GetStreamAsync(url);

      if (IsSvg(url))
        return LoadSvg(stream, width, height);

      return LoadRaster(stream);
    }

    private static Image LoadSvg(Stream stream, int width, int height)
    {
      var svg = new SKSvg();
      svg.Load(stream);

      var pic = svg.Picture;
      var bounds = pic.CullRect;

      using var bitmap = new SKBitmap(width, height);
      using var canvas = new SKCanvas(bitmap);
      canvas.Clear(SKColors.Transparent);

      canvas.Scale(
        width / bounds.Width,
        height / bounds.Height
      );

      canvas.DrawPicture(pic);

      using var image = SKImage.FromBitmap(bitmap);
      using var data = image.Encode(SKEncodedImageFormat.Png, 100);
      using var ms = new MemoryStream(data.ToArray());

      return Image.FromStream(ms);
    }

    private static Image LoadRaster(Stream stream)
    {
      return Image.FromStream(stream);
    }

    private static bool IsSvg(string url)
    {
      return url.EndsWith(".svg", StringComparison.OrdinalIgnoreCase)
             || url.Contains("svg");
    }
  }

}

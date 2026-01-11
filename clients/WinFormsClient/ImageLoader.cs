using Svg;

namespace WinFormsClient;

public static class ImageLoader
{
    private static readonly HttpClient Http = new();

    public static async Task<Image> LoadFromUrlAsync(string url, int width, int height)
    {
        await using var stream = await Http.GetStreamAsync(url);

        if (IsSvg(url))
            return LoadSvg(stream, width, height);

        return LoadRaster(stream);
    }

    private static Image LoadSvg(Stream stream, int width, int height)
    {
        var doc = SvgDocument.Open<SvgDocument>(stream);
        using var bmp = doc.Draw(width, height);
        return (Image)bmp.Clone();
    }

    private static Image LoadRaster(Stream stream)
    {
        return Image.FromStream(stream);
    }

    private static bool IsSvg(string url)
    {
        return url.EndsWith(".svg", StringComparison.OrdinalIgnoreCase) || url.Contains("svg");
    }
}

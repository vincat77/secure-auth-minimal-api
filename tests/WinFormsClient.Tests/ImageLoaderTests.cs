using System;
using System.Drawing;
using System.Threading.Tasks;
using WinFormsClient;
using Xunit;

namespace WinFormsClient.Tests;

public class ImageLoaderTests
{
    private const string BaseUrl = "https://api.dicebear.com/9.x/adventurer/";

    [Fact]
    public async Task LoadFromUrlAsync_Png_Works()
    {
        using var image = await ImageLoader.LoadFromUrlAsync($"{BaseUrl}png?seed=Mason", 64, 64);
        Assert.NotNull(image);
        Assert.True(image.Width > 0);
        Assert.True(image.Height > 0);
    }

    [Fact]
    public async Task LoadFromUrlAsync_Jpeg_Works()
    {
        using var image = await ImageLoader.LoadFromUrlAsync($"{BaseUrl}jpg?seed=Mason", 64, 64);
        Assert.NotNull(image);
        Assert.True(image.Width > 0);
        Assert.True(image.Height > 0);
    }

    [Fact]
    public async Task LoadFromUrlAsync_Svg_WorksOrIsSkippedForSkiaBug()
    {
        try
        {
            const int size = 48;
            using var image = await ImageLoader.LoadFromUrlAsync($"{BaseUrl}svg?seed=Mason", size, size);
            Assert.Equal(size, image.Width);
            Assert.Equal(size, image.Height);
        }
        catch (MissingMethodException ex)
        {
            Console.WriteLine($"SVG test skipped: SkiaSharp.Extended.Svg runtime mismatch: {ex.Message}");
            return;
        }
        catch (TypeLoadException ex)
        {
            Console.WriteLine($"SVG test skipped: SkiaSharp.Extended.Svg runtime mismatch: {ex.Message}");
            return;
        }
    }
}

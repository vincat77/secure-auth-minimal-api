using System;
using System.Windows.Forms;

namespace WinFormsClient;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        // Avvio classico WinForms
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}

using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// The main application class.
    /// </summary>
    public partial class App : Application
    {
        /// <summary>
        /// Initializes the application.
        /// </summary>
        public override void Initialize()
        {
            AvaloniaXamlLoader.Load(this);
        }

        /// <summary>
        /// Called when the framework initialization is complete.
        /// </summary>
        public override void OnFrameworkInitializationCompleted()
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.MainWindow = new MainWindow();
                desktop.Exit += (_, __) => S7_Csharp_Utility.Services.SocatService.KillAllSocatProcesses();
            }

            base.OnFrameworkInitializationCompleted();
        }
    }
}

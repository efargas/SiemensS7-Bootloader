using Avalonia;
using System;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// The main program class responsible for application initialization and configuration.
    /// </summary>
    internal sealed class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// Initialization code. Don't use any Avalonia, third-party APIs or any
        /// SynchronizationContext-reliant code before AppMain is called: things aren't initialized
        /// yet and stuff might break.
        /// </summary>
        /// <param name="args">Command line arguments passed to the application.</param>
        [STAThread]
        public static void Main(string[] args)
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }

        /// <summary>
        /// Builds and configures the Avalonia application with platform detection and logging.
        /// Avalonia configuration, don't remove; also used by visual designer.
        /// </summary>
        /// <returns>The configured app builder instance.</returns>
        public static AppBuilder BuildAvaloniaApp()
            => AppBuilder.Configure<App>()
                .UsePlatformDetect()
                .LogToTrace();
    }
}

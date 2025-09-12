using Avalonia;
using System;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// The main program class.
    /// </summary>
    class Program
    {
        // Initialization code. Don't use any Avalonia, third-party APIs or any
        // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
        // yet and stuff might break.
        [STAThread]
        public static void Main(string[] args) => BuildAvaloniaApp()
            .StartWithClassicDesktopLifetime(args);

        // Avalonia configuration, don't remove; also used by visual designer.
        /// <summary>
        /// Builds the Avalonia application.
        /// </summary>
        /// <returns>The app builder.</returns>
        public static AppBuilder BuildAvaloniaApp()
            => AppBuilder.Configure<App>()
                .UsePlatformDetect()
                // .WithInterFont()
                .LogToTrace();
    }
}

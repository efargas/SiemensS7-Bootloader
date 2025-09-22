using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.DependencyInjection;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.ViewModels;
using S7.Net;
using System;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// The main application class responsible for dependency injection configuration and application lifecycle management.
    /// </summary>
    public partial class App : Application
    {
        /// <summary>
        /// Initializes the application by loading XAML resources.
        /// </summary>
        public override void Initialize()
        {
            AvaloniaXamlLoader.Load(this);
        }

        /// <summary>
        /// Called when the framework initialization is complete.
        /// Configures dependency injection and creates the main window.
        /// </summary>
        public override void OnFrameworkInitializationCompleted()
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                // For now, keep the existing MainWindow creation pattern
                // TODO: Implement full dependency injection in a future update
                desktop.MainWindow = new MainWindow();

                // Handle application exit
                desktop.Exit += OnApplicationExit;
            }

            base.OnFrameworkInitializationCompleted();
        }

        /// <summary>
        /// Handles application exit by cleaning up resources and killing socat processes.
        /// </summary>
        /// <param name="sender">The event sender.</param>
        /// <param name="e">The event arguments.</param>
        private static void OnApplicationExit(object? sender, EventArgs e)
        {
            try
            {
                SocatService.KillAllSocatProcesses();
            }
            catch (Exception ex)
            {
                // Log error but don't prevent application exit
                System.Diagnostics.Debug.WriteLine($"Error during application exit: {ex.Message}");
            }
        }
    }
}

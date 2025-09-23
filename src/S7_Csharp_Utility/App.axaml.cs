using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.DependencyInjection;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.ViewModels;
using S7.Net;
using System;
using System.Linq;
using Avalonia.Threading;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// The main application class responsible for dependency injection configuration and application lifecycle management.
    /// </summary>
    public partial class App : Application
    {
        
        /// <summary>
        /// Gets the service provider.
        /// </summary>
        public IServiceProvider? Services { get; private set; }

        public string[] HexHeader { get; } = Enumerable.Range(0, 16).Select(i => $"{i:X2}").ToArray();


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
                var services = new ServiceCollection();
                ConfigureServices(services);
                Services = services.BuildServiceProvider();

                // This resolves the MainWindow, which in turn resolves its dependencies like the ViewModel.
                desktop.MainWindow = Services.GetRequiredService<MainWindow>();
                var mainViewModel = Services.GetRequiredService<MainWindowViewModel>();

                desktop.MainWindow.Loaded += async (s, e) => await mainViewModel.LoadConfigurationOnStartup();
                desktop.MainWindow.Closing += async (s, e) => await mainViewModel.SaveConfigurationOnExit();
                desktop.Exit += OnApplicationExit;
            }

            base.OnFrameworkInitializationCompleted();
        }

        /// <summary>
        /// Configures the services for the application.
        /// </summary>
        /// <param name="services">The service collection to configure.</param>
        private void ConfigureServices(IServiceCollection services)
        {
            // Register Services
            services.AddSingleton<LoggingService>(_ => new LoggingService(Dispatcher.UIThread));
            services.AddSingleton<SocatLoggerService>(_ => new SocatLoggerService(Dispatcher.UIThread));
            services.AddSingleton<ConfigurationService>();
            services.AddSingleton<PayloadManager>(_ => new PayloadManager(AppContext.BaseDirectory));
            services.AddSingleton<SocatService>();
            services.AddSingleton<PowerController>(sp =>
            {
                var loggingService = sp.GetRequiredService<LoggingService>();
                return new PowerController((message, isError) =>
                    loggingService.Log(message, isError ? LogCategory.Error : LogCategory.Info));
            });

            // Register ViewModels
            services.AddSingleton<MainWindowViewModel>();
            services.AddTransient<PlcConnectionViewModel>();
            services.AddTransient<ModbusPowerSupplyViewModel>();
            services.AddTransient<ConfigurationViewModel>();
            services.AddTransient<FileCompareViewModel>();

            // Register the MainWindow itself. It will act as the root view.
            services.AddSingleton<MainWindow>();

            // Register services
            services.AddSingleton<IDialogService, DialogService>();
            services.AddSingleton<IViewService, ViewService>();
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

using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using S7.Net;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.ViewModels;
using System;
using System.IO;
using System.Linq;

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
        public IServiceProvider Services { get; private set; } = null!;

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

                desktop.MainWindow = Services.GetRequiredService<MainWindow>();
                var mainViewModel = Services.GetRequiredService<MainWindowViewModel>();

                desktop.MainWindow.Loaded += async (s, e) => await mainViewModel.LoadConfigurationOnStartupAsync();
                desktop.MainWindow.Closing += async (s, e) => await mainViewModel.SaveConfigurationOnExitAsync();
                desktop.Exit += (sender, e) => OnApplicationExit(sender, e, Services);
            }

            base.OnFrameworkInitializationCompleted();
        }

        /// <summary>
        /// Configures the services for the application.
        /// </summary>
        /// <param name="services">The service collection to configure.</param>
        private void ConfigureServices(IServiceCollection services)
        {
            // --- Logging ---
            services.AddLogging(configure =>
            {
                configure.AddDebug(); // Add other providers as needed
                // In a real app, you would add a provider that writes to the LogViewModel
            });

            // --- Core Services from S7.Net ---
            services.AddSingleton<PayloadManager>(sp =>
                new PayloadManager(AppContext.BaseDirectory, sp.GetRequiredService<ILogger<PayloadManager>>()));
            services.AddSingleton<ICommunicationChannelFactory, S7.Net.Channels.CommunicationChannelFactory>();

            // --- Utility Project Services ---
            services.AddSingleton<ConfigurationService>(); // Used by other services
            services.AddSingleton<SocatService>();
            services.AddSingleton<IPowerController, PowerControllerAdapter>();
            services.AddSingleton<IFirmwareUnpackingService, FirmwareUnpackingService>();
            services.AddSingleton<IFileComparisonService, FileComparisonService>();
            services.AddSingleton<IProfileManagerService, ProfileManagerService>();
            services.AddSingleton<ISerialPortService, SerialPortService>();
            services.AddSingleton<IApplicationStateService, ApplicationStateService>();
            services.AddSingleton<IDialogService, DialogService>();
            services.AddSingleton<IViewService, ViewService>();

            // --- ViewModels ---
            services.AddSingleton<MainWindowViewModel>();
            services.AddSingleton<LogViewModel>();
            services.AddSingleton<SocatLogViewModel>();
            services.AddTransient<PlcConnectionViewModel>();
            services.AddTransient<ModbusPowerSupplyViewModel>();
            services.AddTransient<ConfigurationViewModel>();
            services.AddTransient<FileCompareViewModel>();
            services.AddTransient<ProfileManagementViewModel>();
            services.AddTransient<FirmwareUnpackerViewModel>(sp =>
                new FirmwareUnpackerViewModel(
                    sp.GetRequiredService<IDialogService>(),
                    sp.GetRequiredService<IFirmwareUnpackingService>(),
                    // This could be sourced from a config service in a real app
                    Path.Combine(AppContext.BaseDirectory, "unpacked_firmware")));

            // --- Views (MainWindow is the root) ---
            services.AddSingleton<MainWindow>();
        }

        /// <summary>
        /// Handles application exit by cleaning up resources and killing socat processes.
        /// </summary>
        private static void OnApplicationExit(object? sender, EventArgs e, IServiceProvider services)
        {
            try
            {
                var socatService = services.GetRequiredService<SocatService>();
                socatService.KillAllSocatProcesses();
            }
            catch (Exception ex)
            {
                // Log error but don't prevent application exit
                System.Diagnostics.Debug.WriteLine($"Error during application exit: {ex.Message}");
            }
        }
    }
}
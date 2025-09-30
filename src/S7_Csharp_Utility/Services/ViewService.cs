using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Microsoft.Extensions.DependencyInjection;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.ViewModels;
using S7_Csharp_Utility.Views;
using System;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// A service for managing view creation and interaction.
    /// </summary>
    public class ViewService : IViewService
    {
        private Window? _mainWindow;
        private readonly IServiceProvider _serviceProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="ViewService"/> class.
        /// </summary>
        /// <param name="serviceProvider">The service provider for resolving dependencies.</param>
        public ViewService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        /// <inheritdoc />
        public Window GetMainWindow()
        {
            if (_mainWindow != null)
                return _mainWindow;

            if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                _mainWindow = desktop.MainWindow;
                return _mainWindow ?? throw new InvalidOperationException("Main window not found");
            }

            throw new InvalidOperationException("Unable to get main window");
        }

        /// <inheritdoc />
        public async Task<DeviceProfile?> ShowProfileManagementWindowAsync()
        {
            var mainWindow = GetMainWindow();
            var viewModel = _serviceProvider.GetRequiredService<ProfileManagementViewModel>();
            var window = new ProfileManagementWindow
            {
                DataContext = viewModel
            };
            return await window.ShowDialog<DeviceProfile?>(mainWindow);
        }

        /// <inheritdoc />
        public void ShowFirmwareUnpackerWindow(string? defaultExtractionPath)
        {
            var mainWindow = GetMainWindow();
            var viewModel = _serviceProvider.GetRequiredService<FirmwareUnpackerViewModel>();
            viewModel.ExtractionPath = defaultExtractionPath ?? string.Empty;

            var window = new FirmwareUnpackerWindow
            {
                DataContext = viewModel
            };
            window.Show(mainWindow);
        }

        /// <inheritdoc />
        public void ShowHexViewerWindow()
        {
            // This view is simple and does not require a complex ViewModel from DI.
            new HexViewerWindow().Show();
        }

        /// <inheritdoc />
        public void ShowSocatLogWindow()
        {
            var mainWindow = GetMainWindow();
            var viewModel = _serviceProvider.GetRequiredService<SocatLogViewModel>();
            var window = new SocatLogWindow
            {
                DataContext = viewModel
            };
            window.Show(mainWindow);
        }

        /// <inheritdoc />
        public async Task ShowComparisonResultAsync(string report)
        {
            var mainWindow = GetMainWindow();
            var window = new ComparisonResultWindow(report);
            await window.ShowDialog(mainWindow);
        }

        /// <inheritdoc />
        public async Task ShowDiffViewAsync(string file1, string file2)
        {
            var mainWindow = GetMainWindow();
            // DiffViewModel is transient and takes parameters, so we create it directly.
            var viewModel = new DiffViewModel(file1, file2);
            var window = new DiffView
            {
                DataContext = viewModel
            };
            await window.ShowDialog(mainWindow);
            viewModel.Dispose();
        }

        /// <inheritdoc />
        public void Exit()
        {
            if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime lifetime)
            {
                lifetime.Shutdown();
            }
        }
    }
}
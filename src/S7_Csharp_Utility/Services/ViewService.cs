using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.Views;
using System;
using Avalonia;

namespace S7_Csharp_Utility.Services
{
    public class ViewService : IViewService
    {
        private Window? _mainWindow;
        private readonly IDialogService _dialogService;

        public ViewService(IDialogService dialogService)
        {
            _dialogService = dialogService;
        }

        public void SetMainWindow(Window mainWindow)
        {
            _mainWindow = mainWindow;
        }

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

        public void ShowProfileManagementWindow(ConfigurationService configService, Action<DeviceProfile> onSetActiveProfile)
        {
            var mainWindow = GetMainWindow();
            new ProfileManagementWindow(configService, onSetActiveProfile).Show(mainWindow);
        }

        public void ShowFirmwareUnpackerWindow(string extractionPath)
        {
            var mainWindow = GetMainWindow();
            new FirmwareUnpackerWindow(extractionPath, _dialogService).Show(mainWindow);
        }

        public void ShowHexViewerWindow()
        {
            new HexViewerWindow().Show();
        }

        public void Exit()
        {
            if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime lifetime)
            {
                lifetime.Shutdown();
            }
        }
    }
}

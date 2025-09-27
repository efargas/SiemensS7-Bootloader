using Avalonia.Controls;
using S7_Csharp_Utility.Services;
using System;

namespace S7_Csharp_Utility.Interfaces
{
    public interface IViewService
    {
        Window GetMainWindow();
        void ShowProfileManagementWindow(Action<DeviceProfile> onSetActiveProfile);
        void ShowFirmwareUnpackerWindow(string extractionPath);
                void Exit();
    }
}

using Avalonia.Controls;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.Services;
using System;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Interfaces
{
    /// <summary>
    /// Defines a service for managing view creation and interaction.
    /// </summary>
    public interface IViewService
    {
        /// <summary>
        /// Gets the main application window.
        /// </summary>
        /// <returns>The main window instance.</returns>
        Window GetMainWindow();

        /// <summary>
        /// Shows the profile management window.
        /// </summary>
        /// <param name="configService">The configuration service.</param>
        /// <param name="onProfileSelected">The action to execute when a profile is selected.</param>
        void ShowProfileManagementWindow(ConfigurationService configService, Action<DeviceProfile?> onProfileSelected);

        /// <summary>
        /// Shows the firmware unpacker window.
        /// </summary>
        /// <param name="defaultExtractionPath">The default path for extracting firmware.</param>
        void ShowFirmwareUnpackerWindow(string? defaultExtractionPath);

        /// <summary>
        /// Shows the hex viewer window.
        /// </summary>
        void ShowHexViewerWindow();

        /// <summary>
        /// Shows the socat log window.
        /// </summary>
        void ShowSocatLogWindow();

        /// <summary>
        /// Shows the comparison result window with the specified report.
        /// </summary>
        /// <param name="report">The comparison report to display.</param>
        Task ShowComparisonResultAsync(string report);

        /// <summary>
        /// Shows the diff view window for comparing two files.
        /// </summary>
        /// <param name="file1">The path to the first file.</param>
        /// <param name="file2">The path to the second file.</param>
        Task ShowDiffViewAsync(string file1, string file2);

        /// <summary>
        /// Exits the application.
        /// </summary>
        void Exit();
    }
}
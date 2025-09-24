using System.Threading.Tasks;

namespace S7_Csharp_Utility.Interfaces
{
    /// <summary>
    /// Defines a service for showing dialogs.
    /// </summary>
    public interface IDialogService
    {
        /// <summary>
        /// Opens a folder picker dialog.
        /// </summary>
        /// <param name="title">The title of the dialog.</param>
        /// <returns>The selected folder path, or null if no folder was selected.</returns>
        Task<string?> OpenFolderPickerAsync(string title);
        /// <summary>
        /// Opens a file picker dialog.
        /// </summary>
        /// <param name="title">The title of the dialog.</param>
        /// <returns>The selected file path, or null if no file was selected.</returns>
        Task<string?> OpenFilePickerAsync(string title);
        /// <summary>
        /// Shows a message dialog.
        /// </summary>
        /// <param name="title">The title of the dialog.</param>
        /// <param name="message">The message to display.</param>
        Task ShowMessageAsync(string title, string message);
        /// <summary>
        /// Shows the socat log window.
        /// </summary>
        void ShowSocatLogWindow();
        /// <summary>
        /// Shows a save file dialog.
        /// </summary>
        /// <param name="title">The title of the dialog.</param>
        /// <param name="defaultExtension">The default file extension.</param>
        /// <param name="fileType">The file type description.</param>
        /// <returns>The selected file path, or null if no file was selected.</returns>
        Task<string?> ShowSaveFileDialogAsync(string title, string defaultExtension, string fileType);
        /// <summary>
        /// Shows an open file dialog.
        /// </summary>
        /// <param name="title">The title of the dialog.</param>
        /// <param name="defaultExtension">The default file extension.</param>
        /// <param name="fileType">The file type description.</param>
        /// <returns>The selected file path, or null if no file was selected.</returns>
        Task<string?> ShowOpenFileDialogAsync(string title, string defaultExtension, string fileType);
    }
}

using System.Threading.Tasks;

namespace S7_Csharp_Utility.Interfaces
{
    public interface IDialogService
    {
        Task<string?> OpenFolderPickerAsync(string title);
        Task<string?> OpenFilePickerAsync(string title);
        Task ShowMessageAsync(string title, string message);
        void ShowSocatLogWindow();
        Task<string?> ShowSaveFileDialogAsync(string title, string defaultExtension, string fileType);
        Task<string?> ShowOpenFileDialogAsync(string title, string defaultExtension, string fileType);
    }
}
